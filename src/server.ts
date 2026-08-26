/**
 * The server: this service's routes, mounted on the kernel.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * THIS FILE USED TO BE THE WHOLE HTTP SURFACE. It is now the seam between two halves:
 *
 *   - `kernel.ts` — the request lifecycle and the reply shapes. Knows no route and no service.
 *   - `routes.ts` — the routes, each handler CLOSED OVER `deps` rather than handed it.
 *
 * `createServer` keeps its signature, its export and its behaviour; every path, status, header,
 * cache directive, CORS decoration and auth check is byte-for-byte what it was. What changed is
 * that the routes can now be mounted by a process that is not this one — the precondition for
 * wave M1 of micro-deploy `docs/service-merge-plan.md`, where lantern absorbs analytics. Nothing
 * is merged; this is the seam only.
 *
 * `ServerDeps`, `PrincipalVerifier` and `READ_SCOPE` are re-exported here because that is where
 * `index.ts`, the tests and the rest of the estate have always imported them from. They are
 * DECLARED in `routes.ts`, beside the handlers that read them.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The surface itself — why OTLP ingest is unauthenticated and `/metrics` is not — is documented at
 * the top of `routes.ts`.
 */

import type { Server } from 'node:http'
import type { Sql } from '@cloudsforge/db'
import type { Metrics } from '@cloudsforge/telemetry'
import { mountRoutes, type RouteSpec } from './kernel.ts'
import { createRoutes, type ServerDeps } from './routes.ts'
import { openIssueCounts } from './issues.ts'

export { READ_SCOPE } from './routes.ts'
export type { PrincipalVerifier, ServerDeps } from './routes.ts'

/** Domain metrics, declared rather than inferred from a log line — AD-20. */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'lantern_up',
      help: 'Always 1. The series that proves the scrape reached Lantern at all.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'lantern_events_ingested_total',
      help: 'Log events stored, by source and severity.',
      kind: 'counter',
      labels: ['source', 'severity'],
    })
    .register({
      name: 'lantern_records_rejected_total',
      help: 'Records refused by a structural limit, by reason. The OTLP partial-success payload.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'lantern_secrets_redacted_total',
      help: 'Credentials removed at ingest before persistence, by kind. A number that should never be zero for long in a real estate.',
      kind: 'counter',
      labels: ['kind'],
    })
    .register({
      name: 'lantern_issues_upserted_total',
      help: 'Issue upserts. One broken deploy is many events and few upserts; the gap is the product working.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'lantern_issues_open',
      help: 'Open issues by severity. This is the map of where the estate is weakest, which is why /metrics is gated.',
      kind: 'gauge',
      labels: ['severity'],
    })
    .register({
      name: 'lantern_rum_samples_total',
      help: 'Browser RUM samples stored, by kind.',
      kind: 'counter',
      labels: ['kind'],
    })
    .register({
      name: 'lantern_rum_rejected_total',
      help: 'RUM posts refused, by reason: origin, quota, envelope, or empty.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'lantern_rum_dropped_total',
      help:
        'Browser samples ACCEPTED BY THE ROUTE AND THEN DISCARDED, by reason. A 2xx with this ' +
        'number climbing is a frontend that believes it is reporting and is not — alert on it.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'lantern_unknown_ingest_path_total',
      help:
        'Posts to an /ingest/* path this service does not serve. Nonzero means a client is ' +
        'configured for a path that does not exist; every event it sends is being lost.',
      kind: 'counter',
      labels: [],
    })
}

/**
 * The listener, lantern's routes only.
 *
 * One line, and it says the whole design: build this service's routes against this service's
 * dependencies, then hand them to a kernel that cannot see either. Kept as its own export because
 * every one of `server.test.ts`'s cases drives exactly this surface, and because a merged listener
 * that could not also be built without the second module would make lantern untestable alone.
 */
export function createServer(deps: ServerDeps): Server {
  return mountRoutes(createRoutes(deps), deps)
}

/**
 * The listener this process actually runs: lantern's routes, then a mounted module's.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **TWO DEPENDENCY BAGS, NEVER ONE.** `deps` is lantern's and nothing else; `mounted` arrived as
 * closures that had already captured a bag this function has no name for. That asymmetry is the
 * merge's central safety property — this signature CANNOT be handed the analytics pepper, because
 * there is no parameter it would arrive through.
 *
 * Order is first-wins, and lantern goes first for two reasons that both matter:
 *
 *   1. `/livez`, `/readyz` and `/metrics` are lantern's in this process (see
 *      `analytics/module.ts`'s `mountableRoutes` for why), and a mounted module must not be able
 *      to shadow them by accident.
 *   2. lantern's `fallback` — the CORS-decorated unknown-`/ingest/*` reply — must remain the miss
 *      for the whole process. `mountRoutes` takes the FIRST fallback in the list and matches none
 *      of them by path, so appending a second module cannot displace it.
 *
 * Checked, not assumed: the two path sets are disjoint apart from the three operational paths.
 * `POST /ingest` (analytics) and `POST /ingest/client` (lantern) compile to `^/ingest$` and
 * `^/ingest/client$`, which cannot both match one request — and the gateway rule was narrowed to
 * `PathPrefix(/ingest/)` in the same wave so the bare `/ingest` is not internet-reachable.
 * `mergedroutes.test.ts` pins all of it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function createMergedServer(deps: ServerDeps, mounted: readonly RouteSpec[]): Server {
  return mountRoutes([...createRoutes(deps), ...mounted], deps)
}

/* ------------------------------------------------------------------ the scrape refresh */

/** Refresh the gauges once per scrape. Bounded queries: the open-issue set is faults, not lines. */
export function scrapeRefresh(deps: { readonly sql: Sql; readonly metrics: Metrics }): () => Promise<void> {
  return async () => {
    deps.metrics.set('lantern_up', 1)
    const counts = await openIssueCounts(deps.sql)
    // Every severity every scrape, including zero: a gauge that simply stops when the last issue in
    // a severity resolves leaves an alert evaluating a stale sample rather than zero.
    for (const severity of ['error', 'fatal', 'warn'] as const) {
      deps.metrics.set('lantern_issues_open', counts.get(severity) ?? 0, { severity })
    }
  }
}
