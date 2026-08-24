/**
 * The HTTP surface.
 *
 * Rule 4 of docs/ecosystem/03 §2: `/livez`, `/readyz` and `/metrics` on every service, or it does
 * not pass CI.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`POST /otlp/v1/logs` IS THE INGEST PATH, AND IT IS THE PRIMARY ONE.**
 *
 * The collector's `otlphttp/lantern` exporter (`deploy/otel/collector.yaml`) posts protobuf
 * here, so this is the door almost every log line in the estate arrives by. It answers WITHOUT a
 * credential — the exporter presents none, by design, because a Lantern outage must not be able to
 * back-pressure the log pipeline into Loki — and it is defended instead by the size, count, depth
 * and attribute limits in `otlp.ts` and by scrubbing every value before it is stored. The
 * Docker-socket collector is a DEV-ONLY fallback (see `env.ts`); push ingest is the real path.
 *
 * The two paths that DO NOT pass through the collector's redaction — this route's siblings, the
 * browser RUM sink and the dev Docker collector — each scrub their own input. "The layer above
 * already does it" is the reason every skipped layer was skipped.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **`/metrics` IS AUTHENTICATED.** 02-target-architecture.md records the estate's own
 * correction: scraping the observation plane "costs a credential, not just a scrape config". This
 * service's `/metrics` publishes which services are producing errors and at what rate — a map of
 * where the estate is weakest — so it is gated by the same `x-lantern-token` the collector and
 * Prometheus already present, checked before the identity JWT so that identity being down does not
 * make the metrics unreadable.
 */

import { timingSafeEqual } from 'node:crypto'
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { ForbiddenError, TokenError, bearerFrom, statusFor, type Principal } from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql, Sql } from '@cloudsforge/db'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import type { Limits } from './env.ts'
import { IngestError, decodeExport } from './otlp.ts'
import { SECRET_KINDS } from './scrub.ts'
import { ingest } from './ingest.ts'
import { RUM_KINDS, RumQuota, fromWire, insertRum, type DropReason, type RumSample } from './rum.ts'
import { listOpenIssues, openIssueCounts } from './issues.ts'
import { eventsByRequestId, listEvents, listRumSamples, traceForRequestId, traceUrl } from './reads.ts'
import type { SecretKind } from './scrub.ts'

export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

export const READ_SCOPE = 'lantern:read'

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  /**
   * The per-network SELECTOR, not a handle. `NetworkSql` has no query methods, so a route that
   * reaches for the process-wide handle instead of `ctx.sql` does not compile — which is the point:
   * a wrong handle is not an error, it is a query that SUCCEEDS against the other estate's rows.
   */
  readonly sql: NetworkSql
  /**
   * The network to assume when no `CF-Network` arrives, or `undefined` to refuse. `CF_NETWORK_SINGLE`,
   * for `pnpm dev`, which has no gateway in front of it. Never set in production.
   */
  readonly singleNetwork?: Network
  /** The static break-glass credential, presented in `x-lantern-token`. See the file header. */
  readonly token: string
  readonly limits: Limits
  /** Browser origins allowed to reach the RUM sink. Empty means the sink is OFF. */
  readonly rumOrigins: readonly string[]
  readonly rumQuota: RumQuota
  /** Where a trace id becomes a link, or '' for no link. */
  readonly traceUrlTemplate: string
  readonly beforeScrape?: () => Promise<void>
}

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

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
  /**
   * The network THIS REQUEST belongs to, from the `CF-Network` header the gateway stamped.
   *
   * Not a property of the process: one pod serves both estates since the network consolidation
   * (micro-deploy `docs/network-consolidation.md`), so "which network am I" has no answer.
   */
  readonly network: Network
  /**
   * The database handle for `network`, resolved ONCE, at the edge of the request.
   *
   * Every route uses this rather than reaching for the process-wide handle, because a wrong handle
   * is not an error — it is a query that SUCCEEDS against the other estate's rows and says nothing.
   * `deps.sql` is a `NetworkSql` with no query methods, so the mistake does not compile.
   */
  readonly sql: Sql
}

/**
 * Routes that answer without belonging to a network.
 *
 * Kubelet probes the first two and Prometheus scrapes the third; none arrives through the gateway,
 * so none carries `CF-Network`. Refusing them makes every health probe a 500 and the pod never
 * becomes ready. Three literal paths rather than a prefix, because this is an exemption from a data
 * boundary; none of them queries the database.
 */
const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

interface Route {
  readonly method: string
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':')
        ? `(?<${segment.slice(1)}>[^/]+)`
        : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number, metricNetwork: string) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method,
        route: routeLabel,
        status: String(status),
        // One target now serves both estates, so the network has to be on the SERIES. Labelled
        // per target it would say nothing — micro-org#398 in a form nothing could recover.
        network: metricNetwork,
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method,
        route: routeLabel,
        network: metricNetwork,
      })
    }

    // ── THE NETWORK, THEN THE HANDLE, BEFORE ANY ROUTE RUNS ──────────────────────────────────
    //
    // `requestNetwork` REFUSES an unstamped request rather than assuming mainnet: a 500 is a
    // routing fault made loud, where a default is a cross-network write nothing would ever flag.
    //
    // The operational endpoints are exempt because kubelet and Prometheus do not come through the
    // gateway and never send the header. Refusing them makes the pod never become ready.
    const networkless = matched !== undefined && OPERATIONAL_ROUTES.has(matched.path)
    let network: Network
    try {
      network = networkless
        ? (deps.singleNetwork ?? deps.sql.networks[0] ?? 'mainnet')
        : requestNetwork(req.headers, deps.singleNetwork ? { fallback: deps.singleNetwork } : {})
    } catch (err) {
      log.error('request carries no usable network', {
        err: err instanceof NetworkUnknownError ? err.message : err,
      })
      send(
        res,
        errorReply(500, 'network_unknown', 'this request could not be attributed to a network', requestId),
        requestId,
      )
      finish(500, 'unknown')
      return
    }

    // ── RESOLVED INSIDE A TRY, AND THAT IS NOT DEFENSIVE PADDING ───────────────────────────────
    //
    // `deps.sql.for()` THROWS when this deployment holds no handle for that network, and that
    // refusal is the safety property the consolidation rests on — better a loud 500 than a query
    // answered out of the other estate's rows.
    //
    // It runs BEFORE `handle` returns a promise, so an uncaught throw escapes the `void` expression
    // past a `.catch` that is not attached yet, and the listener returns having sent NOTHING. The
    // connection then hangs until the client gives up: the one path the design most depends on
    // being loud was the one path that was silent.
    let sql: ReturnType<typeof deps.sql.for>
    try {
      sql = deps.sql.for(network)
    } catch (err) {
      log.error('no usable database handle for this request', { err, network })
      send(
        res,
        errorReply(500, 'network_unavailable', 'this deployment cannot serve that network', requestId),
        requestId,
      )
      finish(500, network)
      return
    }
    void handle(matched, { req, url, requestId, log, params, network, sql }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status, network)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500, network)
      })
  })
}

/**
 * The ingest paths this service actually serves. Published in the unknown-path reply below, so a
 * misconfigured client is told the answer rather than left to guess it.
 */
const SERVED_INGEST_PATHS: readonly string[] = ['POST /otlp/v1/logs', 'POST /ingest/client']

/**
 * Make a refusal on a browser-facing path READABLE BY THE BROWSER.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * A 4xx with no `access-control-allow-origin` is not a 4xx as far as the page is concerned. The
 * fetch rejects with a bare `TypeError: Failed to fetch` and the status, the code and the message
 * are all unreadable — indistinguishable from the host being down. So EVERY refusal on this
 * surface has to carry the headers, not just the happy path and not just the 404.
 *
 * This was found by driving a real Chrome at it. An earlier version of this very change returned a
 * carefully worded 400 explaining the payload mismatch, and the browser could not read one byte of
 * it: `curl` showed the explanation, Chrome showed `Failed to fetch`. A fix for an invisible
 * failure that is itself invisible is not a fix.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Gated on the origin allowlist, so this explains things to a misconfigured frontend without
 * describing the surface to anyone else.
 */
function readableByBrowser(reply: Reply, ctx: RequestContext, deps: ServerDeps): Reply {
  if (!ctx.url.pathname.startsWith('/ingest/')) return reply
  const origin = headerOf(ctx.req, 'origin')
  if (!origin || !deps.rumOrigins.includes(origin)) return reply
  return corsReply(reply, origin)
}

async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  try {
    return await dispatch(route, ctx, deps)
  } catch (err) {
    return readableByBrowser(mapFailure(err, ctx), ctx, deps)
  }
}

async function dispatch(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    // ────────────────────────────────────────────────────────────────────────────────────────
    // WHY AN UNKNOWN /ingest/* PATH IS NOT A BARE 404.
    //
    // Every frontend in the estate posted browser telemetry to `/ingest/browser` for months. This
    // service serves `/ingest/client`. Not one event arrived, and NOBODY SAW IT — because of this
    // exact branch. A cross-origin POST that 404s with no CORS headers is not reported to the page
    // as a 404. The browser refuses to let the script read the response at all and surfaces
    // `net::ERR_FAILED`, which is byte-for-byte what it surfaces when the host is not there.
    // `beacon/src/browser/driver.ts` records the resulting ambiguity: "two real causes,
    // neither" distinguishable — a service that is not deployed, and a path that disagrees.
    //
    // So the fix is not merely to answer; it is to answer WHERE THE CALLER CAN HEAR IT. This reply
    // carries the CORS headers, which is what turns an indistinguishable network failure into a
    // readable 404 naming the paths that do exist. It answers OPTIONS the same way, because a
    // preflight that 404s bare means the POST is never sent and the diagnosis never reached.
    //
    // The origin allowlist still gates it: an unrecognised origin gets the bare 404 it had before.
    // This tells a MISCONFIGURED FRIEND what to fix; it does not map the surface for a stranger.
    // ────────────────────────────────────────────────────────────────────────────────────────
    if (ctx.url.pathname.startsWith('/ingest/')) {
      deps.metrics.increment('lantern_unknown_ingest_path_total', {})
      // Deliberately NOT labelled by path: the caller chooses that string, and a label taken from
      // it is an unbounded-cardinality hole punched straight through to Prometheus.
      ctx.log.warn('post to an unknown ingest path', {
        path: ctx.url.pathname,
        served: SERVED_INGEST_PATHS,
        hint: 'a client is configured for a path this service does not serve',
      })
      const origin = headerOf(ctx.req, 'origin')
      if (origin && deps.rumOrigins.includes(origin)) {
        // The preflight must SUCCEED even though the path does not exist. A 404 here is a failed
        // preflight, the browser never sends the POST, and the 404 body below — the whole
        // diagnosis — is never fetched. Answering 204 costs nothing and is the only way the
        // explanation reaches the page that needs it.
        if (ctx.req.method === 'OPTIONS') return corsReply({ status: 204 }, origin)
        return corsReply(
          {
            status: 404,
            body: {
              error: {
                code: 'unknown_ingest_path',
                message:
                  `this service does not serve ${ctx.req.method} ${ctx.url.pathname}. ` +
                  `The browser sink is POST /ingest/client.`,
                served: SERVED_INGEST_PATHS,
                requestId: ctx.requestId,
              },
            },
          },
          origin,
        )
      }
    }
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  return await route.handle(ctx, deps)
}

/** Map a thrown failure to the reply it deserves. Split out so `handle` can post-process it. */
function mapFailure(err: unknown, ctx: RequestContext): Reply {
  if (err instanceof IngestError) {
    // A refusal from the boundary. It carries the exact status the caller must answer with, and
    // it is INFO not ERROR: a rejected oversized body is the limit working, not a fault.
    ctx.log.info('ingest refused', { code: err.code, status: err.status })
    return errorReply(err.status, err.code, err.message, ctx.requestId)
  }
  const authStatus = statusFor(err)
  if (authStatus === 401) {
    ctx.log.info('unauthenticated request', { err })
    return errorReply(401, 'unauthenticated', 'a valid credential is required', ctx.requestId)
  }
  if (authStatus === 403) {
    const required = err instanceof ForbiddenError ? err.required : 'unknown'
    return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
  }
  if (authStatus === 503) {
    ctx.log.error('token verifier unavailable', { err })
    return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
  }
  if (err instanceof NotFoundError) return errorReply(404, 'not_found', err.message, ctx.requestId)
  if (err instanceof BadRequestError) return errorReply(400, 'bad_request', err.message, ctx.requestId)
  ctx.log.error('unhandled request failure', { err })
  return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
}

function buildRoutes(): Route[] {
  const define = (
    method: string,
    path: string,
    handler: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>,
  ): Route => ({ method, path, pattern: compile(path), handle: handler })

  return [
    define('GET', '/livez', async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() })),

    define('GET', '/readyz', async (_ctx, deps) => {
      const report = await deps.lifecycle.readyz()
      return { status: report.ready ? 200 : 503, body: report }
    }),

    define('GET', '/metrics', async (ctx, deps) => {
      // Gated. An open /metrics here publishes which services are failing and how fast — the shape
      // of the estate's weakness — to anyone who can reach the port.
      await authorise(ctx, deps)
      try {
        await deps.beforeScrape?.()
      } catch (err) {
        ctx.log.warn('gauge refresh failed; serving the previous values', { err })
      }
      return {
        status: 200,
        text: deps.metrics.render(),
        contentType: 'text/plain; version=0.0.4; charset=utf-8',
      }
    }),

    /* ------------------------------------------------------------------ OTLP ingest */

    /**
     * The primary ingest path. Protobuf by default (the collector's `otlphttp` default), JSON
     * accepted for the browser and for `curl`. Unauthenticated by design; defended by limits and
     * scrubbing. The path is fixed by `deploy/otel/collector.yaml` and must not change.
     */
    define('POST', '/otlp/v1/logs', async (ctx, deps) => {
      const body = await readRaw(ctx.req, deps.limits.maxBodyBytes)
      const contentType = headerOf(ctx.req, 'content-type') ?? ''
      const decoded = decodeExport(body, contentType, deps.limits)

      const outcome = await ingest(ctx.sql, decoded.records, 'otlp', deps.limits)

      for (const [severity, count] of outcome.bySeverity) {
        deps.metrics.increment('lantern_events_ingested_total', { source: 'otlp', severity }, count)
      }
      recordSecrets(deps.metrics, outcome.removed)
      if (outcome.issues > 0) deps.metrics.increment('lantern_issues_upserted_total', {}, outcome.issues)

      // Structural rejects come from the decoder's per-record limits; report them in the OTLP
      // partial-success field, which is the protocol's own answer to exactly this.
      let rejected = 0
      for (const [reason, count] of decoded.rejected) {
        rejected += count
        deps.metrics.increment('lantern_records_rejected_total', { reason }, count)
      }

      const partial =
        rejected > 0
          ? { partialSuccess: { rejectedLogRecords: rejected, errorMessage: 'some records exceeded a structural limit' } }
          : { partialSuccess: {} }
      return { status: 200, body: partial }
    }),

    /* ------------------------------------------------------------------ browser RUM / errors */

    /**
     * The browser sink. Origin-allowlisted, per-client quota, no credential, and **no user_id**.
     * Empty `rumOrigins` means the sink is off and every post is refused.
     */
    define('POST', '/ingest/client', async (ctx, deps) => {
      if (deps.rumOrigins.length === 0) {
        deps.metrics.increment('lantern_rum_rejected_total', { reason: 'disabled' })
        throw new NotFoundError('the browser sink is disabled')
      }
      const origin = headerOf(ctx.req, 'origin')
      if (!origin || !deps.rumOrigins.includes(origin)) {
        deps.metrics.increment('lantern_rum_rejected_total', { reason: 'origin' })
        throw new BadRequestError('origin is not allowed')
      }
      const client = clientAddress(ctx.req)
      if (!deps.rumQuota.allow(client)) {
        deps.metrics.increment('lantern_rum_rejected_total', { reason: 'quota' })
        return corsReply({ status: 429, body: { error: { code: 'rate_limited', message: 'too many samples' } } }, origin)
      }

      const raw = await readRaw(ctx.req, deps.limits.maxBodyBytes)
      let parsed: unknown
      try {
        parsed = JSON.parse(raw.toString('utf8'))
      } catch {
        throw new BadRequestError('the request body is not valid JSON')
      }
      const envelope = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : null

      // A body shaped `{"events":[…]}` is the frontends' `src/lib/obs.ts` posting its own envelope.
      // Naming it beats dropping it: unwrapping it here would silently accept a payload whose
      // records are wrong anyway (`type`, not `kind`), and a bare drop is how this hid for months.
      if (envelope && !Array.isArray(envelope['samples']) && Array.isArray(envelope['events'])) {
        deps.metrics.increment('lantern_rum_rejected_total', { reason: 'envelope' })
        throw new BadRequestError(
          'the body carries an "events" array; this sink reads "samples". Each entry needs a "kind" ' +
            `from: ${[...RUM_KINDS].join(', ')} — not a "type".`,
        )
      }

      const wireSamples = Array.isArray(parsed)
        ? parsed
        : envelope && Array.isArray(envelope['samples'])
          ? (envelope['samples'] as unknown[])
          : [parsed]

      const removed = new Map<SecretKind, number>()
      const dropped = new Map<DropReason, number>()
      const samples: RumSample[] = []
      for (const wire of wireSamples.slice(0, deps.limits.maxRecords)) {
        const sample = fromWire(wire, deps.limits, removed, dropped)
        if (sample) samples.push(sample)
      }
      const stored = await insertRum(ctx.sql, samples)
      for (const sample of samples) deps.metrics.increment('lantern_rum_samples_total', { kind: sample.kind })
      recordSecrets(deps.metrics, removed)

      // ──────────────────────────────────────────────────────────────────────────────────────
      // A DROP IS REPORTED, NEVER SWALLOWED.
      //
      // This route used to answer `202 {"stored":0}` for a batch it had discarded in full. That is
      // the worst answer available: the caller is told it succeeded, the operator sees 2xx, and the
      // telemetry is gone. It is the same false-green that let `/ingest/browser` survive — and it
      // would have OUTLIVED the path fix, because a corrected path posting the wrong record shape
      // still lands here and still stores nothing.
      //
      // The count and reasons go in the body so a human driving `curl` sees them, and into a
      // counter so nobody has to be driving `curl`. A batch that was dropped ENTIRELY logs at warn:
      // that is a client which believes it is reporting and is not.
      // ──────────────────────────────────────────────────────────────────────────────────────
      let dropCount = 0
      for (const [reason, count] of dropped) {
        dropCount += count
        deps.metrics.increment('lantern_rum_dropped_total', { reason }, count)
      }
      if (dropCount > 0 && stored === 0) {
        ctx.log.warn('every sample in this batch was dropped', {
          dropped: Object.fromEntries(dropped),
          hint: `a "kind" must be one of: ${[...RUM_KINDS].join(', ')}`,
        })
      }

      return corsReply(
        { status: 202, body: { stored, dropped: dropCount, reasons: Object.fromEntries(dropped) } },
        origin,
      )
    }),

    // The preflight the browser sends before a cross-origin POST with a JSON content type.
    define('OPTIONS', '/ingest/client', async (ctx, deps) => {
      const origin = headerOf(ctx.req, 'origin')
      if (!origin || !deps.rumOrigins.includes(origin)) return { status: 403 }
      return corsReply({ status: 204 }, origin)
    }),

    /* ------------------------------------------------------------------ reads */

    /**
     * The request-id lookup. The workflow the whole service is shaped around: a user reads an id
     * off an error screen, an operator pastes it here, and gets the events and the trace link.
     */
    define('GET', '/v1/requests/:requestId', async (ctx, deps) => {
      await authorise(ctx, deps)
      const requestId = ctx.params['requestId'] ?? ''
      const events = await eventsByRequestId(ctx.sql, requestId)
      const traceId = await traceForRequestId(ctx.sql, requestId)
      return {
        status: 200,
        body: {
          requestId,
          traceId,
          traceUrl: traceUrl(deps.traceUrlTemplate, traceId),
          events,
        },
      }
    }),

    define('GET', '/v1/issues', async (ctx, deps) => {
      await authorise(ctx, deps)
      const limit = clampLimit(ctx.url.searchParams.get('limit'), 100, 500)
      return { status: 200, body: { issues: await listOpenIssues(ctx.sql, limit) } }
    }),

    define('GET', '/v1/events', async (ctx, deps) => {
      await authorise(ctx, deps)
      const events = await listEvents(ctx.sql, {
        ...paramOrUndef(ctx.url.searchParams.get('service'), 'service'),
        ...paramOrUndef(ctx.url.searchParams.get('severity'), 'severity'),
        ...paramOrUndef(ctx.url.searchParams.get('traceId'), 'traceId'),
        limit: clampLimit(ctx.url.searchParams.get('limit'), 100, 1000),
      })
      return { status: 200, body: { events } }
    }),

    /**
     * The browser samples. Credentialled, unlike the sink that writes them.
     *
     * `rum_samples` had no reader at all: an operator could be told a frontend was reporting errors
     * and had no way to look at one. The `attributes` bag comes back with the row because that is
     * where a browser error's `type`, `message` and `stack` live — there are no columns for them.
     */
    define('GET', '/v1/rum', async (ctx, deps) => {
      await authorise(ctx, deps)
      const samples = await listRumSamples(ctx.sql, {
        ...paramOrUndef(ctx.url.searchParams.get('app'), 'app'),
        ...paramOrUndef(ctx.url.searchParams.get('kind'), 'kind'),
        ...paramOrUndef(ctx.url.searchParams.get('session'), 'session'),
        limit: clampLimit(ctx.url.searchParams.get('limit'), 100, 1000),
      })
      return { status: 200, body: { samples } }
    }),
  ]
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

/* ------------------------------------------------------------------ helpers */

function recordSecrets(metrics: Metrics, removed: ReadonlyMap<SecretKind, number>): void {
  for (const kind of SECRET_KINDS) {
    const count = removed.get(kind)
    if (count) metrics.increment('lantern_secrets_redacted_total', { kind }, count)
  }
}

/**
 * Authorise by static token first, then by identity JWT.
 *
 * The static token is checked before the verifier is consulted, so a caller holding it — the
 * collector, Prometheus, an operator with the break-glass secret — is never affected by identity
 * being unreachable, which is precisely the state in which someone is trying to read this service.
 */
async function authorise(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const presented = headerOf(ctx.req, 'x-lantern-token')
  if (presented && constantTimeEquals(presented, deps.token)) {
    return { kind: 'service', service: 'lantern-token', scopes: [READ_SCOPE] }
  }
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  if (!token) throw new TokenError('no credential presented', 'missing')
  const principal = await deps.verifier.principal(token)
  // Any authenticated principal may read: a user token, or a service token carrying the read
  // scope. There is no write surface here for an operator to reach, so read is the only authority.
  if (principal.kind === 'user') return principal
  if (principal.scopes.includes(READ_SCOPE)) return principal
  throw new ForbiddenError(READ_SCOPE)
}

function constantTimeEquals(presented: string, expected: string): boolean {
  const a = Buffer.from(presented)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function clientAddress(req: IncomingMessage): string {
  // Behind the estate's ingress the real client is in `x-forwarded-for`; the socket address is the
  // proxy. First hop only — the rest of the header is attacker-appendable.
  const forwarded = headerOf(req, 'x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0]?.trim() ?? 'unknown'
  return req.socket.remoteAddress ?? 'unknown'
}

function clampLimit(raw: string | null, fallback: number, max: number): number {
  const n = raw === null ? fallback : Number(raw)
  if (!Number.isInteger(n) || n < 1) return fallback
  return Math.min(n, max)
}

function paramOrUndef<K extends string>(value: string | null, key: K): Record<K, string> | Record<string, never> {
  return value && value.length > 0 ? ({ [key]: value } as Record<K, string>) : {}
}

async function readRaw(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > maxBytes) {
      // Refused, not truncated — a truncated protobuf is a different protobuf. Drain is not
      // attempted: the socket is closed under the 413.
      throw new IngestError(413, 'body_too_large', `the request body exceeds ${maxBytes} bytes`)
    }
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function corsReply(reply: Reply, origin: string): Reply & { headers: Record<string, string> } {
  return {
    ...reply,
    headers: {
      'access-control-allow-origin': origin,
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'content-type',
      'access-control-max-age': '600',
      vary: 'origin',
    },
  }
}

function send(res: ServerResponse, reply: Reply & { headers?: Record<string, string> }, requestId: string): void {
  if (res.writableEnded) return
  const hasBody = reply.text !== undefined || reply.body !== undefined
  const payload = reply.text ?? (hasBody ? `${JSON.stringify(reply.body ?? {})}\n` : '')
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    'cache-control': 'no-store',
    ...(reply.headers ?? {}),
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}
