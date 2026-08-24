/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a
 * separate one-shot process — AD-17 and rule 7. Here that matters concretely: below
 * `SCHEMA_VERSION` the `issues_resolved_has_time` and `issues_regressed_has_time` CHECKs and the
 * trace-id shape guards may not exist, and a service that could create them at boot is a service
 * that could start without them.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE OBSERVATION PLANE IS A LEAF.** Nothing here dials another service at boot and nothing blocks
 * on one. The only hard probe is Postgres: without it this service can answer `/livez` and nothing
 * else worth having, because every issue, event and rollup is a row. Identity is not probed at all —
 * `/metrics` and the reads fall back to the static token when identity is down, which is exactly
 * when someone is reading this service.
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
import { createServer, registerServiceMetrics, scrapeRefresh } from './server.ts'
import { registerHandlers, rescheduleRecurring, sampleQueue, seedRecurring } from './jobs.ts'
import { RumQuota } from './rum.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable.

// 2. Telemetry, before anything that can fail, so a pool failure is a structured line rather than a
//    bare V8 stack the collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
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
  ...(sqlTestnet ? { testnet: sqlTestnet as unknown as Sql } : {}),
})

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point.
try {
  await assertSchemaAtLeast(db, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The Lifecycle and its one hard probe, before the routes, because `/readyz` is a route and it
//    needs something to report.
const lifecycle = new Lifecycle({
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})
lifecycle.addProbe(
  postgresProbe('postgres', (signal) =>
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

// 7. Routes. After the Lifecycle so the health handlers report real state.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const refresh = scrapeRefresh({ sql: db, metrics })
const server = createServer({
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
  beforeScrape: async () => {
    await refresh()
    await sampleQueue(queue, metrics)
  },
})

// 8. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving.
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
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
  metrics,
  retention: {
    eventDays: env.eventRetentionDays,
    issueDays: env.issueRetentionDays,
    rollupDays: env.rollupRetentionDays,
    rumDays: env.rumRetentionDays,
  },
})
await seedRecurring(queue)
runner.start()

// 9. Listen. Last of the construction steps: a socket that accepts before its dependencies exist is
//    a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 10. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic.
lifecycle.markReady()

// 11. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and DRAINS, then the pool closes with nothing left.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
