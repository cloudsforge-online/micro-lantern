/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **ONE PROCESS, TWO MODULES — WAVE M1b.** micro-analytics is absorbed here
 * (micro-deploy `docs/service-merge-plan.md`). What that means concretely, and what it does not:
 *
 *   * **One listener**, one port, one `/livez`, one `/readyz`, one `/metrics`. lantern serves all
 *     three; analytics' copies are filtered out where they are built, not deleted.
 *   * **Two databases**, read through their existing variables and never merged. Each module owns
 *     its pools, and each route names the selector its handle comes from — a route that took the
 *     wrong module's database would answer out of the wrong `events` table with a 200.
 *   * **One `Lifecycle`, two hard probes.** `/readyz` reports both databases. A merged readiness
 *     that only probed lantern's would answer 200 while every funnel and every ingest was failing.
 *   * **Two job planes, labelled.** Both modules run a `rollup` and a `retention`; the `module`
 *     label is what keeps `jobs_failed_total` two series instead of one meaningless sum, and what
 *     stops the unlabelled `jobs_pending`/`jobs_overdue` erasing each other every scrape.
 *   * **THIS FILE NEVER HOLDS THE PSEUDONYMISATION PEPPER.** It does not import
 *     `./analytics/env.ts`, `./analytics/pseudonym.ts` or `./analytics/ingest.ts`; it calls one
 *     factory and receives four things, none of which names a secret. See `analytics/module.ts`'s
 *     header for the three layers, and `privacyboundary.test.ts` for the guard.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a
 * separate one-shot process — AD-17 and rule 7. Here that matters concretely: below
 * `SCHEMA_VERSION` the `issues_resolved_has_time` and `issues_regressed_has_time` CHECKs and the
 * trace-id shape guards may not exist, and a service that could create them at boot is a service
 * that could start without them.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE OBSERVATION PLANE IS A LEAF.** Nothing here dials another service at boot and nothing blocks
 * on one. The only hard probes are the two Postgres databases: without them this service can answer
 * `/livez` and nothing else worth having, because every issue, event, rollup and funnel is a row.
 * Identity is not probed at all — `/metrics` and the reads fall back to the static token when
 * identity is down, which is exactly when someone is reading this service.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module via `NODE_OPTIONS`, which
 * reads `OTEL_EXPORTER_OTLP_ENDPOINT` from the environment itself. That is why no `OTEL_*` variable
 * appears in `src/env.ts`.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, networkSql, type Sql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createMergedServer, registerServiceMetrics, scrapeRefresh } from './server.ts'
import { registerHandlers, rescheduleRecurring, sampleQueue, seedRecurring } from './jobs.ts'
import { RumQuota } from './rum.ts'
import { createAnalyticsModule } from './analytics/module.ts'

/** This module's own metric label. See `analytics/module.ts`'s `MODULE_LABEL` for the argument. */
const MODULE_LABEL = 'lantern'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable. `./analytics/module.ts` imports its own
//    `env.ts`, which does the same for the analytics half — so a merged pod refuses to boot unless
//    BOTH configurations are complete, rather than serving half a telemetry plane.

// 2. Telemetry, before anything that can fail, so a pool failure is a structured line rather than a
//    bare V8 stack the collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})

// ══════════════════════════════════════════════════════════════════════════════════════════════
// ONE REGISTRY, AND A LABELLED VIEW FOR EACH MODULE'S JOB PLANE.
//
// `metrics` is THE registry. It is what `/metrics` renders, what the three `register*` helpers
// write specs into, and what the kernel writes `http_requests_total` through — deliberately
// unlabelled there, because one listener serves both modules and the `route` label already says
// which. `/metrics` renders THIS object and not a view: rendering a view works, because a view
// shares the registry's series maps by reference, but it reads as though the view owned the
// endpoint, and that is what the next person adding a third module would copy.
//
// `jobMetrics` is lantern's view, and it exists for one measured collision. Both modules register a
// job `kind="rollup"` and a `kind="retention"`, so `jobs_failed_total{kind="rollup"}` would be the
// SUM of two unrelated queues — a number with no meaning that an alert would still fire on. And
// `jobs_pending`/`jobs_overdue` are worse, because they carry no `kind` at all: each module's
// `sampleQueue` writes the IDENTICAL series, so one OVERWRITES the other every scrape and a wedged
// queue is ABSENT from the graph rather than high. Nobody alerts on absent.
//
// The label is stamped rather than declared because widening every spec's `labels` would push
// `module` onto every call site in the estate, including the single-service ones that have nothing
// to say about it — see `Metrics.withLabels`.
// ══════════════════════════════════════════════════════════════════════════════════════════════
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
const jobMetrics = metrics.withLabels({ module: MODULE_LABEL })

logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  // Said at boot, because a sink that is switched off looks exactly like one that is broken until
  // somebody reads the environment.
  rumSink: env.rumOrigins.length > 0,
  dockerCollector: env.dockerCollector,
})

// 3. The database pool. Opened before the schema assertion (which is a query) and before the
//    Lifecycle (whose readiness probe closes over it).
const poolOptions = {
  max: env.databasePoolMax,
  onnotice: () => {},
}
const sql = postgres(env.databaseUrl, poolOptions)
const db = sql as unknown as Sql

// ── ONE POOL PER NETWORK THIS DEPLOYMENT SERVES ─────────────────────────────────────────────────
//
// `LANTERN_DATABASE_URL_TESTNET` unset is the single-network case: `networkSql` then holds one
// handle and REFUSES a testnet request rather than answering it out of mainnet rows. That refusal
// is the whole safety property — a substituted handle is a query that SUCCEEDS and says nothing.
const sqlTestnet = env.databaseUrlTestnet ? postgres(env.databaseUrlTestnet, poolOptions) : undefined
// ── WHICH ESTATE THIS DEPLOYMENT IS ─────────────────────────────────────────────────────────
//
// The `networkSql` key below used to be the literal `mainnet`. Same image, same code,
// different env — so the TESTNET pod registered its testnet DSN under the name `mainnet` and
// then refused every request the gateway stamped `CF-Network: testnet`, because it genuinely
// held no handle by that name. Five services crash-looped on it within ten minutes of the
// first deploy: the refusal was right, the registration was wrong.
//
// `CF_NETWORK_SINGLE` is how a single-network pod says which estate it is. The render sets it
// for every deployment; `mainnet` remains the default only for a bare `pnpm dev`.
const ownNetwork = (env.singleNetwork || 'mainnet') as 'mainnet' | 'testnet'

const networks = networkSql({
  [ownNetwork]: db,
  ...(sqlTestnet && ownNetwork !== 'testnet' ? { testnet: sqlTestnet as unknown as Sql } : {}),
})

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point.
try {
  await assertSchemaAtLeast(db, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The Lifecycle and its hard probes, before the routes, because `/readyz` is a route and it
//    needs something to report.
const lifecycle = new Lifecycle({
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})
lifecycle.addProbe(
  postgresProbe('postgres-lantern', (signal) =>
    Promise.race([
      sql`select 1`,
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
      }),
    ]),
  ),
)

// 6. The queue and the runner.
const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId, leaseMs: 120_000 })

// 7. The identity verifier. ONE for the process: both modules read the same JWKS, and two clients
//    would mean two caches, two refreshes and two ways to be stale.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })

// ══════════════════════════════════════════════════════════════════════════════════════════════
// 8. THE ANALYTICS MODULE.
//
// Built before the routes, because its routes are mounted with lantern's and its probe belongs on
// the Lifecycle the health handlers report. It throws rather than exiting — the exit code is this
// file's to choose, and a module that killed the process would take lantern's log ingest down for
// an analytics fault without a line saying so.
//
// **Four things come back and none of them is a secret.** There is no `PepperRing` in this scope,
// no `ANALYTICS_PSEUDONYM_KEY`, and no analytics `env` import above — which is why no lantern
// handler can close over the pepper even by mistake.
// ══════════════════════════════════════════════════════════════════════════════════════════════
let analytics: Awaited<ReturnType<typeof createAnalyticsModule>>
try {
  analytics = await createAnalyticsModule({
    metrics,
    verifier,
    claimingJobs: () => lifecycle.claimingJobs,
  })
} catch (err) {
  logger.fatal('the analytics module could not start', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}
lifecycle.addProbe(analytics.probe)
logger.info('analytics module ready', { schemaVersion: analytics.schemaVersion })

// 9. Routes. After the Lifecycle so the health handlers report real state, and after the analytics
//    module so both tables are mounted on one listener.
const refresh = scrapeRefresh({ sql: db, metrics })
const server = createMergedServer(
  {
    lifecycle,
    logger,
    metrics,
    verifier,
    sql: networks,
    // The fallback for a request with no `CF-Network` header — which is EVERY service-to-service
    // call, because those go container to container and never reach the gateway that stamps one.
    // `requestNetwork` still prefers the header, so this cannot mask a mis-stamped external
    // request; it only answers the internal callers that never had one.
    singleNetwork: ownNetwork,
    token: env.token,
    limits: env.limits,
    rumOrigins: env.rumOrigins,
    rumQuota: new RumQuota(env.rumQuotaPerMinute),
    traceUrlTemplate: env.traceUrlTemplate,
    // Gauges are sampled at scrape time rather than on a timer. There is no `setInterval` in this
    // repository and CI greps for one — rule 8.
    //
    // BOTH modules' gauges, because there is one `/metrics` and a module whose gauges were never
    // refreshed would publish the values it happened to hold at boot — which reads as a queue that
    // is permanently empty rather than one nobody is sampling.
    beforeScrape: async () => {
      await refresh()
      await sampleQueue(queue, jobMetrics)
      await analytics.beforeScrape()
    },
  },
  analytics.routes,
)

// 10. The job runners, started before `listen()`. Background work is claimed under a lease, so a
//     replica that is draining stops claiming before it stops serving.
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    // EVERY line here goes through the labelled view. `kind` alone is not enough: the other module
    // registers the same two kinds, and a counter summing two unrelated queues is worse than no
    // counter, because it still moves.
    if (event.kind) {
      if (event.type === 'claimed') jobMetrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') jobMetrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') jobMetrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') jobMetrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        jobMetrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})
registerHandlers(runner, {
  sql: db,
  logger,
  metrics: jobMetrics,
  retention: {
    eventDays: env.eventRetentionDays,
    issueDays: env.issueRetentionDays,
    rollupDays: env.rollupRetentionDays,
    rumDays: env.rumRetentionDays,
  },
})
await seedRecurring(queue)
runner.start()
analytics.start()

// 11. Listen. Last of the construction steps: a socket that accepts before its dependencies exist is
//     a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 12. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic — and it
//     answers for BOTH databases, because both probes are on this Lifecycle.
lifecycle.markReady()

// 13. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runners stop claiming and DRAIN, then the pools close with nothing left.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  await sqlTestnet?.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
// Registered after lantern's two, so it runs BEFORE them — hooks run in reverse registration order
// and the one below (the server) is therefore first of all. The sequence a SIGTERM produces is:
// stop accepting, drain and close analytics, drain and close lantern. Both runners have already
// stopped CLAIMING by then, because `claimingJobs` above is the host's and both read it.
lifecycle.onShutdown(async () => {
  await analytics.stop()
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
