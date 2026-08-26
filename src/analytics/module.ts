/**
 * The analytics module: this half of the merged process, constructed behind one function.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS FILE IS THE PRIVACY BOUNDARY, AND IT IS THE ONLY PLACE `ANALYTICS_PSEUDONYM_KEY` IS
 * REACHABLE FROM.**
 *
 * Wave M1b (micro-deploy `docs/service-merge-plan.md`) folds analytics into lantern's process. The
 * plan's one non-negotiable is that "the privacy boundary survives as a module boundary instead of
 * a process boundary". A convention would not do that: two services sharing a process share a heap,
 * and the pepper is the one value in this estate whose disclosure is not "an attacker can act as
 * us" but "the pseudonymisation was never real" — with it and a candidate user id, anyone can
 * compute a lookup key and learn whether that person is in the store.
 *
 * So the boundary is made out of SCOPE, in three layers, each of which fails closed on its own:
 *
 *   1. **`./env.ts` is imported HERE and nowhere above.** The pepper values enter the process in
 *      this file's import graph and in no other. `src/index.ts` — the merged composition root —
 *      does not import `./analytics/env.ts`, `./analytics/pseudonym.ts` or `./analytics/ingest.ts`,
 *      so it never holds a `PepperRing` and therefore cannot pass one anywhere.
 *   2. **`AnalyticsModule` carries no pepper-bearing field.** What this function RETURNS is four
 *      things the host process needs — routes, a readiness probe, a scrape hook and a lifetime —
 *      and none of them names a secret. The host could not put the pepper in lantern's deps if it
 *      wanted to, because it is never handed one.
 *   3. **Each module's handlers close over their OWN deps** (wave M1a's seam). `handle` takes only
 *      `ctx`, so lantern's OTLP handler has no `deps` parameter to reach through.
 *
 * `src/privacyboundary.test.ts` fails if any of the three is edited away, and it is written so that
 * it cannot pass by finding nothing.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Everything below is `analytics/src/index.ts` as it stood, in the same order and for the same
 * stated reasons. What changed is only what a module in somebody else's process cannot own: the
 * listener, the `Lifecycle`, the `Verifier` and the `Metrics` registry are the HOST's and are
 * passed in; the database pools, the pepper ring, the job queue and the job runner are this
 * module's and are built here.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a
 * separate one-shot process — AD-17 and rule 7. Here it matters concretely: below `SCHEMA_VERSION`
 * the four constraints this module's privacy properties rest on — `events_subject_shape`,
 * `events_person_has_pseudonym`, `events_props_allowed` and `subject_keys_erased` — may not exist,
 * and code that could create them at boot is code that could start without them. It asserts the
 * version and refuses to serve below it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PRODUCT ANALYTICS PLANE IS A LEAF.** Nothing here dials another service at boot and nothing
 * blocks on one. The only hard probe is Postgres: without it this module can answer nothing worth
 * having, because every event, cohort and funnel is a row. Identity is a SOFT probe — `/metrics`
 * falls back to the static token, and a funnel that cannot be read for ten minutes is not a reason
 * to take a replica out of the balancer. 13-operational-model.md classifies this plane as "durable
 * but lossy by design", which is the same judgement.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A subscription that does not exist misses the events it was not there for.** The estate's
 * outbox relay does not redeliver an event published while nothing was subscribed, so this
 * module's history begins the day its subscription does. There is no backfill and there cannot be
 * one — the producers' outboxes are pruned. The README says so where a product manager will read it.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql, networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import type { Lifecycle, Probe } from '@cloudsforge/lifecycle'
import { postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, type Metrics } from '@cloudsforge/telemetry'
import type { RouteSpec, RequestContext } from '../kernel.ts'
import { OPERATIONAL_ROUTES } from '../kernel.ts'
import { SERVICE, env } from './env.ts'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION } from './migrations.ts'
import { createRoutes } from './routes.ts'
import { registerServiceMetrics, scrapeRefresh, type PrincipalVerifier } from './server.ts'
import { registerHandlers, rescheduleRecurring, sampleQueue, seedRecurring } from './jobs.ts'
import { publish } from './definitions.ts'
import { PepperRing } from './pseudonym.ts'
import type { Db } from './store.ts'
import type { Target } from '../migratortargets.ts'

/**
 * The label every metric this module writes carries.
 *
 * `registerJobMetrics` names queues by `kind`, and both modules register a `rollup` and a
 * `retention`. Without this, `jobs_failed_total{kind="rollup"}` is the SUM of two unrelated jobs —
 * and `jobs_pending`/`jobs_overdue`, which carry no `kind` at all, are worse: each module's sample
 * OVERWRITES the other's, so a wedged queue is absent from the graph rather than high.
 */
export const MODULE_LABEL = 'analytics'

/** What the host process supplies. Deliberately nothing this module could hide a secret inside. */
export interface HostRuntime {
  /**
   * The process-wide registry — the object the host's `/metrics` renders, not a view of it.
   *
   * This module registers its `analytics_*` specs on it directly (those names collide with
   * nothing) and writes its JOB metrics through `metrics.withLabels({ module })`, which is the
   * family that does collide — see `MODULE_LABEL`. A view shares the registry's spec and series
   * maps by reference, so one endpoint carries both modules either way.
   */
  readonly metrics: Metrics
  /** The host's identity verifier. One JWKS client for the process; both modules read it. */
  readonly verifier: PrincipalVerifier
  /**
   * The host `Lifecycle`'s `claimingJobs`, as a function.
   *
   * A function and not the `Lifecycle` itself, deliberately. This module has no business marking
   * the process ready or draining it — those are the host's, and one of the two ways a merged
   * process goes wrong is a module deciding a lifetime it does not own. What it DOES need is the
   * one bit: a replica that has begun draining must stop claiming jobs before it stops serving, in
   * BOTH modules, or the drain window is spent running work the pod is about to abandon.
   */
  claimingJobs(): boolean
}

/**
 * What the host process gets back. **No field here names a secret, and that is the point** — see
 * the file header, layer 2.
 */
export interface AnalyticsModule {
  /**
   * The routes to mount beside lantern's, each already closed over this module's deps AND stamped
   * with this module's database selector. The three operational paths are NOT among them; see
   * `mountableRoutes` below.
   */
  readonly routes: readonly RouteSpec<Sql>[]
  /**
   * The readiness probe for THIS module's database, for the host's one `Lifecycle`.
   *
   * Hard, and that is the whole reason it is returned rather than kept: a merged `/readyz` that
   * probed only lantern's database would answer 200 while every funnel, cohort and ingest was
   * failing, and the balancer would keep sending traffic to it. A merged readiness that does not
   * reflect both halves is a regression on two working services.
   */
  readonly probe: Probe
  /** Sample this module's gauges. Called from the host's `/metrics`, never on a timer — rule 8. */
  beforeScrape(): Promise<void>
  /** Start claiming jobs. Called after the schema is asserted and before the socket accepts. */
  start(): void
  /** Stop claiming, drain, and close the pools. Registered on the host's shutdown hooks. */
  stop(): Promise<void>
  /** For the host's boot line. The version `assertSchemaAtLeast` was satisfied at. */
  readonly schemaVersion: number
}

/**
 * Build the analytics half of this process.
 *
 * Throws rather than calling `process.exit`: the host owns the exit code, because a module that
 * killed the process would take lantern down for an analytics fault at a point where the host has
 * a logger and a `fatal` line to write. Every failure below was an `exit(1)` in the standalone
 * service and still stops the boot — it just stops it one frame further out.
 */
export async function createAnalyticsModule(host: HostRuntime): Promise<AnalyticsModule> {
  // 1. Environment. Importing `./env.ts` validated it; a missing or placeholder pepper has already
  //    exited with a structured line naming the variable and never its value.

  // 2. Telemetry.
  //
  //    `metrics` is the HOST's registry — the object `/metrics` renders. Specs registered on it are
  //    on that page, and this module's domain names are all `analytics_`-prefixed, so nothing there
  //    collides with anything.
  //
  //    `jobMetrics` is this module's labelled VIEW, and it exists for the one family that DOES
  //    collide. See `MODULE_LABEL`: the two modules register the same job kinds, and
  //    `jobs_pending`/`jobs_overdue` carry no kind at all. A view writes into the same series maps,
  //    so both modules are still on one page — see `Metrics.withLabels`.
  const metrics = host.metrics
  const jobMetrics = metrics.withLabels({ module: MODULE_LABEL })
  const logger = new Logger({
    service: SERVICE,
    level: env.logLevel,
    version: env.version,
    env: env.env,
    // The pepper is never passed to a logger, but a redaction key costs nothing and closes the
    // accident where somebody logs the whole config object while debugging.
    redactKeys: ['pseudonymKey', 'pseudonymKeys', 'pepper', 'peppers', 'deliverySecrets'],
  })
  registerServiceMetrics(metrics)
  logger.info('starting', {
    version: env.version,
    schemaVersion: SCHEMA_VERSION,
    // Said at boot, because a threshold somebody raised in an incident and forgot to lower is
    // otherwise invisible until a dashboard is unexpectedly empty.
    minCohort: env.minCohort,
    eventRetentionDays: env.eventRetentionDays,
  })

  // 3. The database pool. Opened before the schema assertion (which is a query) and before the
  //    probe (which closes over it).
  const poolOptions = { max: env.databasePoolMax, onnotice: () => {} }
  const sql = postgres(env.databaseUrl, poolOptions)

  // ── ONE HANDLE PER NETWORK THIS DEPLOYMENT SERVES ────────────────────────────────────────────
  //
  // `ANALYTICS_DATABASE_URL_TESTNET` unset is the single-network case, which is every deployment
  // until the consolidation reaches this module. `networkSql` then holds one handle and REFUSES a
  // testnet request rather than answering it out of mainnet rows.
  const sqlTestnet = env.databaseUrlTestnet ? postgres(env.databaseUrlTestnet, poolOptions) : undefined
  const db = sql as unknown as Sql

  const close = async (): Promise<void> => {
    await sql.end({ timeout: 5 }).catch(() => {})
    await sqlTestnet?.end({ timeout: 5 }).catch(() => {})
  }

  // 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point: see
  //    the file header for which four constraints would otherwise be optional.
  try {
    await assertSchemaAtLeast(db, SCHEMA_VERSION)
  } catch (err) {
    await close()
    throw err
  }

  // 5. Publish this build's metric definitions. Before serving, because a chart read against an
  //    unpublished definition is a number nobody can explain afterwards — and because `publish`
  //    THROWS if a released definition's text changed, which must stop the deploy rather than
  //    surface as a 409 on an operator's first click.
  try {
    const published = await publish(sql as unknown as never)
    logger.info('metric definitions published', { ...published })
  } catch (err) {
    await close()
    throw err
  }

  // 6. The queue and the runner's dependencies.
  const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId, leaseMs: 120_000 })

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

  // ── THIS MODULE'S SELECTOR, AND WHY EVERY ROUTE BELOW CARRIES IT ────────────────────────────
  //
  // The kernel resolves ONE handle per request, from one selector. In a merged process the host's
  // selector is lantern's, so a route mounted without this would read lantern's database: a query
  // that succeeds against the wrong `events` table and reports nothing. `RouteSpec.sql` is where
  // that is answered, and stamping it here — once, over the whole table — is why no handler had to
  // change.
  const analyticsSql = networkSql({
    [ownNetwork]: sql as unknown as RuntimeSql,
    ...(sqlTestnet && ownNetwork !== 'testnet' ? { testnet: sqlTestnet as unknown as RuntimeSql } : {}),
  })

  const refresh = scrapeRefresh({ sql, metrics })

  // 7. The routes, over THIS module's deps. `createRoutes` is where the pepper is read and it is
  //    the last frame that can see one — every handler it returns has closed over it.
  const routes = mountableRoutes(
    createRoutes({
      // The host's, so `/readyz` and `/livez` — which this module no longer serves — still see one
      // truth, and so a drain drains both halves at once.
      lifecycle: NO_LIFECYCLE,
      logger,
      metrics,
      verifier: host.verifier,
      sql: analyticsSql,
      // The fallback for a request with no `CF-Network` header — which is EVERY service-to-service
      // call, because those go container to container and never reach the gateway that stamps one.
      // `requestNetwork` still prefers the header, so this cannot mask a mis-stamped external
      // request; it only answers the internal callers that never had one.
      singleNetwork: ownNetwork,
      token: env.token,
      minCohort: env.minCohort,
      queue,
      ingest: {
        sql,
        logger,
        metrics,
        secrets: env.deliverySecrets,
        peppers: new PepperRing(env.pseudonymKeys, env.pseudonymVersion),
      },
      // Unused: `/metrics` is the host's and calls `beforeScrape()` below directly. Left off rather
      // than wired to nothing, so nobody reads this as a second scrape path.
    }),
    analyticsSql,
  )

  // 8. The job runner. Started by `start()`, after the host has finished booting.
  const reschedule = rescheduleRecurring(queue, logger)
  const runner = new JobRunner({
    queue,
    concurrency: 2,
    pollMs: 1_000,
    // Both halves of the answer. `started` is this module's own gate — nothing may be claimed
    // before the host has finished booting — and `host.claimingJobs()` is the drain, which is the
    // host's to decide and must apply to both modules at once.
    shouldClaim: () => started && host.claimingJobs(),
    onEvent: (event) => {
      // EVERY line here goes through the labelled view. `kind` alone is not enough: the other
      // module registers the same two kinds, and a counter summing two unrelated queues is worse
      // than no counter, because it still moves.
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
  let started = false
  registerHandlers(runner, {
    sql,
    logger,
    metrics: jobMetrics,
    retention: {
      eventDays: env.eventRetentionDays,
      rollupDays: env.rollupRetentionDays,
      inboxDays: env.inboxRetentionDays,
      idempotencyDays: env.idempotencyTtlDays,
    },
    cohortWeeks: env.cohortWeeks,
  })

  return {
    routes,
    probe: postgresProbe('postgres-analytics', (signal) =>
      Promise.race([
        sql`select 1`,
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
        }),
      ]),
    ),
    beforeScrape: async () => {
      await refresh()
      // The view, not the registry. `jobs_pending` and `jobs_overdue` carry no `kind`, so this one
      // line is where the two modules would otherwise erase each other every scrape.
      await sampleQueue(queue, jobMetrics)
    },
    start: () => {
      started = true
      void seedRecurring(queue)
        .then(() => runner.start())
        .catch((err: unknown) => logger.error('failed to seed recurring jobs', { err }))
    },
    stop: async () => {
      started = false
      const clean = await runner.stop(20_000)
      logger.info('job runner stopped', { clean })
      await close()
      logger.info('database pool closed')
    },
    schemaVersion: SCHEMA_VERSION,
  }
}

/**
 * The databases this module owns, for the merged migrator.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE MIGRATOR MUST NOT IMPORT `./env.ts` EITHER, AND THIS IS WHY IT DOES NOT HAVE TO.**
 *
 * `src/migrator.ts` needs two facts about this module — where its databases are and what to apply
 * to them — and it needed them badly enough that the first version of it imported this module's
 * `env` wholesale. That is the whole configuration record, `pseudonymKeys` included: a second
 * entry point holding the pepper, in a process nobody thinks of as serving anything.
 *
 * It is a real hole rather than a stylistic one. The migrator runs as an init container with the
 * same environment as the service, so the pepper is genuinely present in it; what decides whether
 * a stack trace, a log line or a crash dump from that process can carry the value is whether any
 * binding there can reach it. This function returns four scalars and an array of DDL, so none can.
 *
 * `privacyboundary.test.ts` is what noticed, on the first run of the guard it was written to be.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function analyticsMigrationTargets(): readonly Target[] {
  const common = { module: SERVICE, migrations: MIGRATIONS, baselineVersion: BASELINE_VERSION } as const
  return [
    { ...common, network: 'primary', url: env.databaseUrl },
    // One entry until this module's testnet database is adopted into this cluster
    // (`docs/network-consolidation.md` §6), two afterwards. Migrating only the first is the failure
    // that would not show up: the migrator exits 0, the deploy goes green, and the NEXT release's
    // boot-time schema assertion finds the second database behind and refuses to serve testnet.
    ...(env.databaseUrlTestnet ? [{ ...common, network: 'testnet', url: env.databaseUrlTestnet }] : []),
  ]
}

/**
 * Drop the three operational paths from a mounted module's table, and stamp its selector on the
 * rest.
 *
 * ── WHY THE DROP, AND WHY IT IS A FILTER RATHER THAN A DELETION ────────────────────────────────
 *
 * One process serves ONE `/livez`, ONE `/readyz` and ONE `/metrics`; mounting two of each would
 * make the second unreachable — first-wins matching — which is a shadowed handler nobody would
 * ever notice was dead. lantern's win, for one reason that is not a preference: Prometheus scrapes
 * this target under lantern's job with `x-lantern-token`, and the collector and every runbook
 * present the same header. An analytics `/metrics` here would 401 the estate's only scraper.
 *
 * Nothing is lost by it. `/metrics` renders the host's registry, which this module's views write
 * into, so every `analytics_*` series is on the merged page; `beforeScrape` above is what keeps
 * its gauges fresh, and `probe` is what keeps `/readyz` honest about this module's database.
 *
 * It is a filter and NOT a deletion from `routes.ts` because that table is also the standalone
 * service's, which is still deployed until cutover — and because `routeidempotency.test.ts`
 * derives its route list from that file and counts what it finds. Deleting three routes there
 * would move a source-level detector's floor for a reason that has nothing to do with idempotency.
 */
function mountableRoutes(
  specs: readonly RouteSpec<Db>[],
  sql: ReturnType<typeof networkSql>,
): readonly RouteSpec<Sql>[] {
  return specs
    .filter((spec) => !OPERATIONAL_ROUTES.has(spec.path))
    .map((spec) => ({
      method: spec.method,
      path: spec.path,
      sql,
      // The one cast at this seam, and it is the same one the kernel makes internally: `Db` and
      // `Sql` are two published views of the driver's client, so this names which view the handler
      // reads through and never a different value.
      handle: (ctx: RequestContext<Sql>) => spec.handle(ctx as unknown as RequestContext<Db>),
    }))
}

/**
 * The `Lifecycle` shape `createRoutes` demands for the three routes this module no longer mounts.
 *
 * `ServerDeps.lifecycle` exists for `/livez` and `/readyz`, both of which are filtered out above,
 * so no handler that survives the filter can reach it. Passing the HOST's real Lifecycle would be
 * worse than useless: it would suggest those two handlers are live when they are not, and it is
 * exactly the kind of "wired to something plausible" that makes dead code look alive.
 *
 * It throws rather than returning a plausible answer, so if the filter is ever removed the
 * shadowed route fails loudly on its first request instead of reporting a readiness it did not
 * compute.
 */
const NO_LIFECYCLE: Lifecycle = {
  livez: () => {
    throw new Error('analytics does not serve /livez in the merged process — lantern does')
  },
  readyz: () => {
    throw new Error('analytics does not serve /readyz in the merged process — lantern does')
  },
} as unknown as Lifecycle
