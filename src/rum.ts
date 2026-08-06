/**
 * The browser RUM / client-error sink.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THERE IS NO user_id, AND THE FIELD IS DROPPED AT INGEST.**
 *
 * 11-data-and-contract-strategy.md says of this plane: "Nothing to do — expires within 30 days,
 * and holds no `user_id` by policy". The frozen browser sink breaks exactly that policy —
 * `stack/infra/lantern/src/server.js` writes `userId: item.userId`. There is no column to store
 * one in here (migration 4), `fromWire` deletes the field whatever a page sends, and a test plants
 * one and asserts it never reaches the database.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * This is one of the two paths that reach the service WITHOUT passing through the collector's
 * key-based redaction (the dev Docker collector is the other), so it scrubs its own attributes and
 * strings — defence in depth, because "the layer above already does it" is the reason every skipped
 * layer was skipped. It answers WITHOUT a credential — a browser holds none — so it is defended by
 * an origin allowlist and a per-client quota instead. Empty `rumOrigins` means the sink is off.
 */

import type { Sql } from '@cloudsforge/db'
import type { Limits } from './env.ts'
import { scrubString, scrubValue, type SecretKind } from './scrub.ts'

export const RUM_KINDS: ReadonlySet<string> = new Set([
  'page_load',
  'first_contentful_paint',
  'largest_contentful_paint',
  'fetch_error',
  'unhandled_rejection',
  'error',
])

export interface RumSample {
  readonly app: string
  readonly kind: string
  readonly route: string | null
  readonly valueMs: number | null
  readonly statusCode: number | null
  readonly requestId: string | null
  readonly traceId: string | null
  readonly session: string | null
  readonly attributes: Record<string, unknown>
}

function clampInt(value: unknown, min: number, max: number): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN
  if (!Number.isFinite(n)) return null
  const t = Math.trunc(n)
  return t >= min && t <= max ? t : null
}

function stringOrNull(value: unknown, limits: Limits): string | null {
  if (typeof value !== 'string' || value.length === 0) return null
  return scrubString(value).value.slice(0, limits.maxStringBytes)
}

function hexOrNull(value: unknown, length: number): string | null {
  if (typeof value !== 'string') return null
  const lower = value.toLowerCase()
  if (lower.length !== length || !/^[0-9a-f]+$/.test(lower) || /^0+$/.test(lower)) return null
  return lower
}

/**
 * Why a wire record was not kept.
 *
 * A CLOSED set, because these are metric labels and a browser chooses the input. Deriving a label
 * from the payload — the offending `kind` string, say — would let any page mint unbounded series
 * in the estate's Prometheus by posting junk.
 */
export type DropReason = 'not_an_object' | 'unknown_kind' | 'missing_app'

/**
 * One wire sample to a stored sample. Returns null for a record this service will not keep — an
 * unknown `kind`, or a missing `app` — so one bad entry in a batch drops itself rather than the
 * batch. **`userId` and any other identifying field are simply never read.**
 *
 * `dropped` tallies the reasons, exactly as `removed` tallies redactions. It is an out-parameter
 * rather than a return shape because the reason must survive all the way to the RESPONSE: a sink
 * that returns null here and `202 {"stored":0}` at the boundary is a sink that discards a
 * frontend's entire telemetry stream while telling it everything is fine. That is not a
 * hypothetical — it is what this service did to sixteen frontends until it was driven.
 */
export function fromWire(
  raw: unknown,
  limits: Limits,
  removed: Map<SecretKind, number>,
  dropped?: Map<DropReason, number>,
): RumSample | null {
  const drop = (reason: DropReason): null => {
    if (dropped) dropped.set(reason, (dropped.get(reason) ?? 0) + 1)
    return null
  }

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return drop('not_an_object')
  const wire = raw as Record<string, unknown>

  const kind = typeof wire['kind'] === 'string' ? wire['kind'] : ''
  if (!RUM_KINDS.has(kind)) return drop('unknown_kind')
  const app = stringOrNull(wire['app'], limits)
  if (app === null) return drop('missing_app')

  // The attribute bag is scrubbed, and `userId`/`user`/`email` are not promoted to columns and are
  // scrubbed-by-key if named sensitively; but the guarantee that matters is structural — there is
  // nowhere to persist an identity, so an attribute carrying one expires with the row in 30 days.
  const attrsIn = wire['attributes']
  const attributes =
    typeof attrsIn === 'object' && attrsIn !== null && !Array.isArray(attrsIn)
      ? (scrubValue(attrsIn, removed) as Record<string, unknown>)
      : {}

  return {
    app,
    kind,
    route: stringOrNull(wire['route'], limits),
    valueMs: clampInt(wire['valueMs'] ?? wire['value_ms'], 0, 600_000),
    statusCode: clampInt(wire['statusCode'] ?? wire['status_code'], 0, 999),
    requestId: stringOrNull(wire['requestId'] ?? wire['request_id'], limits),
    traceId: hexOrNull(wire['traceId'] ?? wire['trace_id'], 32),
    session: stringOrNull(wire['session'], limits),
    attributes,
  }
}

/** Insert a batch of samples. One multi-row statement, same reasoning as `ingestEvents`. */
export async function insertRum(sql: Sql, samples: readonly RumSample[]): Promise<number> {
  if (samples.length === 0) return 0
  // app, kind, route, value_ms, status_code, request_id, trace_id, session, attributes.
  const columns = 9
  const params: unknown[] = []
  const tuples: string[] = []
  samples.forEach((sample, row) => {
    const base = row * columns
    const holes = Array.from({ length: columns }, (_unused, i) => `$${base + i + 1}`)
    holes[columns - 1] = `${holes[columns - 1]}::jsonb`
    tuples.push(`(${holes.join(',')})`)
    params.push(
      sample.app,
      sample.kind,
      sample.route,
      sample.valueMs,
      sample.statusCode,
      sample.requestId,
      sample.traceId,
      sample.session,
      // The OBJECT, not `JSON.stringify` of it. postgres.js serialises a bound object to JSON
      // itself, so pre-stringifying hands it a *string* to serialise and the column ends up
      // holding a JSON string — `jsonb_typeof` says 'string' and `attributes->>'kind'` is null.
      // Every attribute a browser sends is then stored and unreadable. See `attributesRoundTrip`
      // in `rum.test.ts`, which reads the column back out of Postgres rather than trusting this.
      sample.attributes ?? {},
    )
  })
  await sql.unsafe(
    `insert into rum_samples (app, kind, route, value_ms, status_code, request_id, trace_id, session, attributes)
     values ${tuples.join(',')}`,
    params,
  )
  return samples.length
}

/**
 * A per-client fixed-window quota, in process.
 *
 * In-process and honest about it: the RUM sink is best-effort browser telemetry, a replica restart
 * simply resets the window, and a cross-replica quota would need a round trip to the database on a
 * path that must stay cheap. The window is coarse (one minute) so the map stays small and old
 * entries are reclaimed lazily on the next hit from the same client.
 */
export class RumQuota {
  readonly #perMinute: number
  readonly #now: () => number
  readonly #windows = new Map<string, { start: number; count: number }>()

  constructor(perMinute: number, now: () => number = () => Date.now()) {
    this.#perMinute = perMinute
    this.#now = now
  }

  /** True if this client may post now. Increments its counter when it may. */
  allow(client: string): boolean {
    const now = this.#now()
    const minute = Math.floor(now / 60_000)
    const entry = this.#windows.get(client)
    if (!entry || entry.start !== minute) {
      this.#windows.set(client, { start: minute, count: 1 })
      // Opportunistic sweep: keep the map from growing without bound under a spray of client
      // addresses. Bounded work — at most the map size, and only when it is large.
      if (this.#windows.size > 10_000) {
        for (const [key, value] of this.#windows) if (value.start !== minute) this.#windows.delete(key)
      }
      return true
    }
    if (entry.count >= this.#perMinute) return false
    entry.count += 1
    return true
  }
}
