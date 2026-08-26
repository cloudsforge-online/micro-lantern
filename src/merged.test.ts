/**
 * The merged surface: both modules, one listener, driven over a real socket against BOTH databases.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS IS THE ONLY TEST THAT SEES WHAT THE PROCESS ACTUALLY IS.**
 *
 * `server.test.ts` drives lantern alone and `analytics/server.test.ts` drives analytics alone, and
 * both still pass unchanged — which is the point of the M1a seam, and also the reason neither can
 * see any of the four things a merge can break:
 *
 *   1. **A route reading the wrong module's database.** The kernel resolves ONE handle per request
 *      from ONE selector. Mounted without `RouteSpec.sql`, analytics' handlers would be handed
 *      lantern's `events` table — a query that succeeds against the wrong rows and reports nothing.
 *      Neither single-module suite can see it, because in each of them there is only one database.
 *   2. **Two `/livez`, `/readyz`, `/metrics`.** Matching is first-wins, so the second copy of each
 *      is simply dead — and a dead health endpoint looks exactly like a live one.
 *   3. **A `/readyz` that reports half the process.** Lantern's Lifecycle probing only lantern's
 *      database answers 200 while every funnel and every ingest is failing.
 *   4. **Job metrics that erase each other.** `jobs_pending` and `jobs_overdue` carry no `kind`, so
 *      before the `module` label each `sampleQueue` OVERWROTE the other's series and a wedged queue
 *      was ABSENT from the graph rather than high.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Two databases are required, and the suite skips without both. It is the one file in this
 * repository that needs `ANALYTICS_TEST_DATABASE_URL` and `LANTERN_TEST_DATABASE_URL` at once, and
 * `service-ci.yml` provides exactly that — one CI database per declared variable, for the reason
 * `migratortargets.test.ts` measures: both modules own a table called `events`.
 */

import assert from 'node:assert/strict'
import { randomBytes, randomUUID } from 'node:crypto'
import { after, before, describe, it } from 'node:test'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type postgres from 'postgres'
import { networkSql } from '@cloudsforge/db'
import { JobQueue, type Sql as JobsSql } from '@cloudsforge/jobs'
import { TokenError, type Principal } from '@cloudsforge/auth'
import { Lifecycle, postgresProbe } from '@cloudsforge/lifecycle'
import { Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { createMergedServer, registerServiceMetrics, scrapeRefresh } from './server.ts'
import { sampleQueue } from './jobs.ts'
import { RumQuota } from './rum.ts'
import type { Limits } from './env.ts'
import type { PrincipalVerifier } from './routes.ts'
import {
  db,
  migrateTestDb,
  openDb,
  quietLogger,
  resetLantern,
  skip as lanternSkip,
  enabled as lanternEnabled,
} from './testsupport.ts'
import {
  migrateTestDb as migrateAnalyticsDb,
  openDb as openAnalyticsDb,
  resetAnalytics,
  enabled as analyticsEnabled,
  TEST_DSN_VAR as ANALYTICS_TEST_DSN_VAR,
} from './analytics/testsupport.ts'

/*
 * ── THE ANALYTICS MODULE VALIDATES ITS CONFIGURATION AT IMPORT AND EXITS ON A BAD ONE ──────────
 *
 * Right for a service, fatal for a test runner — `analytics/env.test.ts` records the same problem
 * and solves it the same way. So a complete environment is populated FIRST and the module is then
 * imported dynamically.
 *
 * The values are generated per run rather than written as literals, for the reason that file states
 * at length: a hyphenated placeholder that clears a length check is the exact family of value the
 * estate actually shipped, and no repository should hold a string that looks like a pepper.
 *
 * The DSN is this suite's own test database, so the module's analytics half reads the same database
 * `resetAnalytics` truncates.
 */
process.env['ANALYTICS_DATABASE_URL'] =
  process.env[ANALYTICS_TEST_DSN_VAR] ?? ['postgres://u:p@127.0.0.1:5432', 'unset_test'].join('/')
process.env['ANALYTICS_PSEUDONYM_KEY'] ??= randomBytes(48).toString('base64')
process.env['ANALYTICS_TOKEN'] ??= randomBytes(48).toString('base64')
process.env['ANALYTICS_DELIVERY_SECRETS'] ??= randomBytes(48).toString('base64')
process.env['IDENTITY_JWKS_URL'] ??= 'http://127.0.0.1:4001/.well-known/jwks.json'
process.env['IDENTITY_ISSUER'] ??= 'http://127.0.0.1:4001'
const { createAnalyticsModule } = await import('./analytics/module.ts')

const ANALYTICS_TOKEN = process.env['ANALYTICS_TOKEN'] ?? ''
const LANTERN_TOKEN = 'a-real-looking-static-token-000000000'

const LIMITS: Limits = {
  maxBodyBytes: 4 * 1024 * 1024,
  maxRecords: 5_000,
  maxAttributes: 128,
  maxDepth: 8,
  maxStringBytes: 8_192,
}

/** Accepts one bearer as an operator, because analytics' reads refuse a plain user by design. */
const verifier: PrincipalVerifier = {
  async principal(token: string): Promise<Principal> {
    if (token === 'good-operator') return { kind: 'user', userId: 'u1', handle: 'op', roles: ['admin'] }
    throw new TokenError('bad token', 'invalid')
  },
}

const skip = lanternEnabled && analyticsEnabled ? false : lanternSkip || `set ${ANALYTICS_TEST_DSN_VAR}`

describe('the merged surface', { skip }, () => {
  let lanternSql: postgres.Sql
  let analyticsSql: postgres.Sql
  let analytics: Awaited<ReturnType<typeof createAnalyticsModule>>
  let server: Server
  let url: string
  let registry: Metrics
  let stopped = false

  before(async () => {
    lanternSql = openDb()
    await migrateTestDb(lanternSql)
    await resetLantern(lanternSql)

    analyticsSql = openAnalyticsDb()
    await migrateAnalyticsDb(analyticsSql)
    await resetAnalytics(analyticsSql)

    // Exactly the arrangement `index.ts` builds: ONE registry rendered by /metrics, a labelled view
    // per module for the JOB plane only, one Lifecycle with two hard probes, both route tables on
    // one listener.
    registry = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
    const jobMetrics = registry.withLabels({ module: 'lantern' })

    analytics = await createAnalyticsModule({ metrics: registry, verifier, claimingJobs: () => false })

    // `cacheMs: 0` because a case below asserts what /readyz says a moment AFTER a database goes
    // away, and the default one-second cache would answer with the report from before it did.
    const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100, cacheMs: 0 })
    lifecycle.addProbe(postgresProbe('postgres-lantern', () => lanternSql`select 1`))
    lifecycle.addProbe(analytics.probe)

    const queue = new JobQueue(lanternSql as unknown as JobsSql, { owner: 'merged-test', leaseMs: 120_000 })
    const refresh = scrapeRefresh({ sql: db(lanternSql), metrics: registry })
    server = createMergedServer(
      {
        lifecycle,
        logger: quietLogger(),
        // The REGISTRY, not a view: /metrics renders this object, and the kernel's HTTP metrics are
        // process-wide — one listener serves both modules and `route` already says which.
        metrics: registry,
        verifier,
        sql: networkSql({ mainnet: db(lanternSql) }),
        singleNetwork: 'mainnet' as const,
        token: LANTERN_TOKEN,
        limits: LIMITS,
        rumOrigins: ['http://app.example'],
        rumQuota: new RumQuota(1000),
        traceUrlTemplate: 'https://tempo.example/trace/{traceId}',
        beforeScrape: async () => {
          await refresh()
          await sampleQueue(queue, jobMetrics)
          await analytics.beforeScrape()
        },
      },
      analytics.routes,
    )
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    lifecycle.markReady()
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  })

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
    if (!stopped) await analytics.stop()
    await lanternSql.end({ timeout: 5 }).catch(() => {})
    await analyticsSql.end({ timeout: 5 }).catch(() => {})
  })

  /* ---------------------------------------------------------------- route table */

  describe('the two route tables are mounted, and neither shadows the other', () => {
    it("answers lantern's reads", async () => {
      const res = await fetch(`${url}/v1/issues`, { headers: { 'x-lantern-token': LANTERN_TOKEN } })
      assert.equal(res.status, 200)
    })

    it("answers analytics' reads on the SAME listener and the SAME port", async () => {
      const res = await fetch(`${url}/catalogue`, { headers: { authorization: 'Bearer good-operator' } })
      assert.equal(res.status, 200)
      const body = (await res.json()) as { events: string[] }
      assert.ok(body.events.length > 0, 'the catalogue is analytics data served through lantern’s listener')
    })

    it('keeps POST /ingest and POST /ingest/client apart, which is why the gateway rule matters', async () => {
      // `^/ingest$` and `^/ingest/client$` cannot both match one request. The bare `/ingest` is
      // analytics' bus inbox and is MAC-authenticated; the gateway rule was narrowed to
      // `PathPrefix(/ingest/)` in the same wave so it is not internet-reachable at all.
      const bare = await fetch(`${url}/ingest`, { method: 'POST', body: '{}' })
      // No signature: analytics refuses it. What matters is that it reached ANALYTICS — lantern's
      // unknown-ingest-path fallback would have answered 404 with `unknown_ingest_path`.
      assert.equal(bare.status, 401)
      assert.equal(((await bare.json()) as { error: { code: string } }).error.code, 'bad_signature')

      const client = await fetch(`${url}/ingest/client`, {
        method: 'POST',
        headers: { origin: 'http://app.example', 'content-type': 'application/json' },
        body: JSON.stringify({ samples: [] }),
      })
      assert.equal(client.status, 202, "lantern's browser sink still answers on its own path")
    })

    it("lantern's unknown-/ingest/* fallback is still the miss for the whole process", async () => {
      const res = await fetch(`${url}/ingest/browser`, {
        method: 'POST',
        headers: { origin: 'http://app.example', 'content-type': 'application/json' },
        body: '[]',
      })
      assert.equal(res.status, 404)
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, 'unknown_ingest_path')
    })
  })

  /* ---------------------------------------------------------------- the right database */

  describe("every analytics route reads ANALYTICS' database, not the host's", () => {
    it('serves a table that exists only in the analytics schema', async () => {
      // `rejections` is analytics'. Lantern's database has no such table, so a route handed the
      // host's selector would 500 here rather than answer — which is the whole reason
      // `RouteSpec.sql` exists.
      const res = await fetch(`${url}/rejections`, { headers: { authorization: 'Bearer good-operator' } })
      assert.equal(res.status, 200)
      const body = (await res.json()) as { days: number; rejections: unknown[] }
      assert.equal(body.days, 7)
      assert.ok(Array.isArray(body.rejections))
    })

    it("reads the ANALYTICS events table, and lantern's identically-named one is not it", async () => {
      /*
       * ══════════════════════════════════════════════════════════════════════════════════════════
       * BOTH MODULES OWN A TABLE CALLED `events`, WITH DIFFERENT COLUMNS.
       *
       * A row is planted in each. The analytics read must answer from the schema that has
       * `subject_key` and `event_name` in it; run against lantern's `events` — which has `service`,
       * `severity` and `msg` — the same statement is a 500, and mounted without `RouteSpec.sql`
       * that is exactly where it would have run.
       * ══════════════════════════════════════════════════════════════════════════════════════════
       */
      await lanternSql`
        insert into events (ts, service, source, severity, msg)
        values (now(), 'merged-test', 'otlp', 'error', 'a lantern event, not an analytics one')
      `
      await analyticsSql`
        insert into events (subject_key, subject_kind, event_name, occurred_at, session, props,
                            source_event_id, source_topic, producer)
        values (${'a'.repeat(64)}, 'user', 'session_started', now(), null, ${analyticsSql.json({})},
                ${randomUUID()}, 'identity.session.started', 'identity')
      `

      const res = await fetch(`${url}/reports/daily?event=session_started`, {
        headers: { authorization: 'Bearer good-operator' },
      })
      assert.equal(res.status, 200, 'against lantern’s events table this statement is a 500')
      const body = (await res.json()) as { event: string; minCohort: number; points: unknown[] }
      assert.equal(body.event, 'session_started')
      assert.ok(body.minCohort >= 1, 'the k-anonymity floor still governs the merged read')
      assert.ok(Array.isArray(body.points))
    })

    it("and lantern's reads still see lantern's rows", async () => {
      const res = await fetch(`${url}/v1/events?service=merged-test`, {
        headers: { 'x-lantern-token': LANTERN_TOKEN },
      })
      assert.equal(res.status, 200)
      const body = (await res.json()) as { events: Array<{ service: string }> }
      assert.equal(body.events.length, 1)
      assert.equal(body.events[0]?.service, 'merged-test')
    })
  })

  /* ---------------------------------------------------------------- one of each infra route */

  describe('one process serves exactly one of each operational route', () => {
    it('/livez answers 200', async () => {
      assert.equal((await fetch(`${url}/livez`)).status, 200)
    })

    it('/metrics is gated by the LANTERN token, which is what Prometheus presents', async () => {
      // Prometheus scrapes this target under lantern's job with `x-lantern-token`, and so do the
      // collector and every runbook. An analytics `/metrics` mounted here would 401 all of them.
      const res = await fetch(`${url}/metrics`, { headers: { 'x-lantern-token': LANTERN_TOKEN } })
      assert.equal(res.status, 200)
    })

    it('and the analytics token now opens nothing', async () => {
      // Stated as a test rather than in a comment, because it is the one operational consequence of
      // the merge a deploy has to know: `ANALYTICS_TOKEN` gated exactly one thing — that service's
      // `/metrics` — and in this process it gates nothing. It is still REQUIRED by
      // `analytics/env.ts`, because the standalone service is deployed until cutover.
      const res = await fetch(`${url}/metrics`, { headers: { 'x-analytics-token': ANALYTICS_TOKEN } })
      assert.equal(res.status, 401)
    })
  })

  /* ---------------------------------------------------------------- one /metrics, two modules */

  describe('/metrics carries both modules, and their job series do not erase each other', () => {
    it("renders both modules' domain metrics from one registry", async () => {
      const text = await scrape()
      assert.match(text, /lantern_up/, "lantern's series must be on the merged page")
      assert.match(text, /analytics_events_stored/, "analytics' series must be on the merged page")
    })

    it('keeps jobs_pending as TWO series, one per module', async () => {
      /*
       * ════════════════════════════════════════════════════════════════════════════════════════
       * THE COLLISION THIS WHOLE LABEL EXISTS FOR.
       *
       * `jobs_pending` and `jobs_overdue` carry no `kind`. Two modules calling
       * `metrics.set('jobs_pending', …)` against one registry write the IDENTICAL series, so
       * whichever samples last erases the other — and a wedged queue is then not "high" on the
       * graph, it is ABSENT from it. Nobody alerts on absent.
       *
       * `withLabels` makes each module's write a different series. Both must be present after ONE
       * scrape, which is the only arrangement in which the erasure could have happened.
       * ════════════════════════════════════════════════════════════════════════════════════════
       */
      const lines = (await scrape()).split('\n')
      for (const metric of ['jobs_pending', 'jobs_overdue']) {
        const series = lines.filter((line) => line.startsWith(`${metric}{`))
        assert.ok(
          series.some((line) => line.includes('module="lantern"')),
          `${metric} has no lantern series — the analytics sample erased it:\n${series.join('\n')}`,
        )
        assert.ok(
          series.some((line) => line.includes('module="analytics"')),
          `${metric} has no analytics series — the lantern sample erased it:\n${series.join('\n')}`,
        )
        assert.equal(series.length, 2, `${metric} must be exactly two series, one per module`)
      }
    })

    it('labels the counters that DO carry a kind, so two rollups are two series', async () => {
      // Both modules register a job `kind="rollup"` and a `kind="retention"`. Summing them would
      // produce a number an alert still fires on and nobody can act on.
      registry.withLabels({ module: 'analytics' }).increment('jobs_failed_total', { kind: 'rollup' })
      registry.withLabels({ module: 'lantern' }).increment('jobs_failed_total', { kind: 'rollup' })

      const failed = (await scrape()).split('\n').filter((line) => line.startsWith('jobs_failed_total{'))
      const rollups = failed.filter((line) => line.includes('kind="rollup"'))
      assert.equal(rollups.length, 2, `two modules' rollups must be two series:\n${failed.join('\n')}`)
      for (const line of rollups) assert.match(line, / 1$/, 'each module counts its own failure, not the sum')
    })

    it('renders the REGISTRY, so nothing about the page depends on which module wrote a series', async () => {
      // `/metrics` is handed the registry itself, not a view. Rendering a view would work — a view
      // shares the registry's series maps — but it reads as though the view owned the endpoint, and
      // that is what the next person adding a third module would copy. The observable half is
      // asserted here: every series, whoever wrote it, on one page.
      const text = await scrape()
      assert.match(text, /analytics_subjects_live/, "a lantern-only render would omit analytics' gauges")
      assert.match(text, /lantern_issues_open/)
      // And the process-wide HTTP metrics are NOT stamped with a module: one listener serves both,
      // and the `route` label already says which. A module label here would be a lie for half the
      // series on the page.
      const http = text.split('\n').filter((line) => line.startsWith('http_requests_total{'))
      assert.ok(http.length > 0, 'the kernel must have recorded the requests this suite made')
      for (const line of http) {
        assert.ok(!line.includes('module='), `http_requests_total must not claim a module: ${line}`)
      }
    })

    async function scrape(): Promise<string> {
      const res = await fetch(`${url}/metrics`, { headers: { 'x-lantern-token': LANTERN_TOKEN } })
      assert.equal(res.status, 200)
      return await res.text()
    }
  })

  /* ---------------------------------------------------------------- readiness covers both */

  describe('/readyz reflects BOTH databases', () => {
    it('names a hard probe for each module, and both pass', async () => {
      const res = await fetch(`${url}/readyz`)
      assert.equal(res.status, 200)
      const body = (await res.json()) as { ready: boolean; checks: Array<{ name: string; state: string }> }
      assert.equal(body.ready, true)
      assert.deepEqual(
        body.checks.map((c) => c.name).sort(),
        ['postgres-analytics', 'postgres-lantern'],
        'a merged /readyz that probes one database answers 200 while the other half is dead, and ' +
          'the balancer keeps sending traffic to it',
      )
      for (const check of body.checks) assert.equal(check.state, 'pass', `${check.name} must be passing`)
    })

    // LAST, because it destroys the analytics half on purpose. It is the regression the plan names
    // in so many words, and the only way to prove it is to take that database away and read the
    // endpoint the load balancer reads.
    it('goes UNREADY when the analytics database is the one that has gone', async () => {
      await analytics.stop()
      stopped = true

      const res = await fetch(`${url}/readyz`)
      const body = (await res.json()) as { ready: boolean; checks: Array<{ name: string; state: string }> }
      const analyticsCheck = body.checks.find((c) => c.name === 'postgres-analytics')
      assert.notEqual(analyticsCheck, undefined, 'the analytics probe must still be reported')
      assert.notEqual(analyticsCheck?.state, 'pass', "analytics' database is gone and /readyz must say so")
      assert.equal(res.status, 503)
      assert.equal(body.ready, false)

      // And lantern's is still fine, so this is not "everything broke" — it is one module reported
      // honestly, which is exactly what a merged readiness has to be able to do.
      assert.equal(body.checks.find((c) => c.name === 'postgres-lantern')?.state, 'pass')
    })
  })
})
