/**
 * The HTTP kernel: matching, the request lifecycle, and the shapes a route answers in.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **NO ROUTE LIVES HERE, AND NOTHING HERE KNOWS WHAT THIS SERVICE IS.** This file imports the
 * runtime packages and `node:http` and nothing else from `src/` — no store, no decoder, no domain
 * error. That is the whole point of it: `mountRoutes` can be handed one service's routes or two
 * services' routes concatenated, and it cannot tell the difference.
 *
 * The seam exists so that a second telemetry module can be mounted in this process without
 * re-implementing the request lifecycle — the network attribution, the per-request handle, the
 * in-flight gauge and the duration histogram — which is exactly the code that is dangerous to
 * write twice (micro-deploy `docs/service-merge-plan.md`, wave M1).
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql, Sql } from '@cloudsforge/db'
import { newRequestId, type Logger, type Metrics } from '@cloudsforge/telemetry'

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/

export interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
  /**
   * Extra response headers, merged over the defaults `send` writes.
   *
   * `send` has always honoured this — it took `Reply & { headers?: … }` — while `Reply` itself did
   * not declare it, so `corsReply` had to widen its own return type to say what it produced and
   * every caller that merely PASSED a reply along lost the field from the type. Declared here, so
   * the CORS decoration survives being handed through a helper.
   */
  readonly headers?: Record<string, string>
}

export interface RequestContext {
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
export const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

/**
 * One route, as the module that owns it declares it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`handle` TAKES ONLY `ctx`.** It used to take `(ctx, deps)`, which made every route a function
 * of the ONE dependency bag the process happened to have. Two modules in one process do not share
 * one bag — they have different databases, different secrets and, for the analytics side, a
 * pseudonymisation pepper that must not be reachable from anywhere else — so a `deps` parameter
 * threaded by the kernel would have to become a union, and the privacy boundary would be a
 * convention instead of a scope. Closing over deps at construction time makes it a scope.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export interface RouteSpec {
  readonly method: string
  readonly path: string
  readonly handle: (ctx: RequestContext) => Promise<Reply>
  /**
   * This spec answers only when NOTHING else matched, and it is never matched by path.
   *
   * The 404 is not plumbing in this estate: an unknown `/ingest/*` path has to be answered where a
   * browser can read it, and which paths exist is a property of the routes that were mounted, not
   * of the kernel. So the module owning the routes owns the miss too. `method` and `path` on a
   * fallback are labels only — `path` is what the metrics call an unmatched request.
   *
   * The FIRST fallback in the list wins; mount exactly one.
   */
  readonly fallback?: true
}

/** A `RouteSpec` with its path compiled. Built by `mountRoutes`, never by a route module. */
export interface Route {
  readonly method: string
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext) => Promise<Reply>
}

export function compile(path: string): RegExp {
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

/**
 * What the request lifecycle itself needs — and deliberately nothing a route needs.
 *
 * A service's own `ServerDeps` extends this, so `mountRoutes(createRoutes(deps), deps)` typechecks
 * while the kernel still cannot see the token, the verifier or the limits.
 */
export interface MountDeps {
  readonly logger: Logger
  readonly metrics: Metrics
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
}

/**
 * Mount a set of route specs on a `node:http` server.
 *
 * Everything between the socket and `handle(ctx)` is here: the request id, the URL, matching, the
 * network attribution, the per-request database handle, the in-flight gauge and the two HTTP
 * metrics. A route module supplies specs and never sees any of it.
 */
export function mountRoutes(specs: readonly RouteSpec[], deps: MountDeps): Server {
  const routes: Route[] = []
  let fallback: RouteSpec | undefined
  for (const spec of specs) {
    if (spec.fallback) {
      fallback ??= spec
      continue
    }
    routes.push({ method: spec.method, path: spec.path, pattern: compile(spec.path), handle: spec.handle })
  }
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
    void answer(matched ?? fallback, { req, url, requestId, log, params, network, sql })
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
 * Run the chosen handler, or answer the bare 404 when nothing matched and no fallback was mounted.
 *
 * `async` rather than a bare call so a handler that throws SYNCHRONOUSLY becomes a rejected promise
 * the `.catch` above is already attached to, rather than a throw escaping the `void` expression.
 */
async function answer(
  route: { readonly handle: (ctx: RequestContext) => Promise<Reply> } | undefined,
  ctx: RequestContext,
): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  return await route.handle(ctx)
}

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
export function readableByBrowser(
  reply: Reply,
  ctx: RequestContext,
  deps: { readonly rumOrigins: readonly string[] },
): Reply {
  if (!ctx.url.pathname.startsWith('/ingest/')) return reply
  const origin = headerOf(ctx.req, 'origin')
  if (!origin || !deps.rumOrigins.includes(origin)) return reply
  return corsReply(reply, origin)
}

export function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

export function corsReply(reply: Reply, origin: string): Reply {
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

export function send(res: ServerResponse, reply: Reply, requestId: string): void {
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

export function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}
