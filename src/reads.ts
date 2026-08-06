/**
 * The read paths: the request-id lookup that is this service's primary human workflow, the event
 * and issue lists, and the once-per-scrape gauge refresh.
 *
 * 13-operational-model.md — "a user quotes an id from an error screen and an operator pastes
 * it into one search box". That is `eventsByRequestId` and the partial `events_request_id_idx`
 * behind it, and `traceForRequestId` is what turns the paste into a jump to Tempo.
 */

import type { Sql } from '@cloudsforge/db'

export interface EventRow {
  readonly id: string
  readonly ts: Date
  readonly service: string
  readonly source: string
  readonly severity: string
  readonly msg: string
  readonly request_id: string | null
  readonly trace_id: string | null
  readonly span_id: string | null
  readonly route: string | null
  readonly status_code: number | null
  readonly latency_ms: number | null
  readonly err_type: string | null
  readonly fingerprint: string | null
  readonly attributes: Record<string, unknown>
}

/**
 * `attributes` is selected.
 *
 * It was not, and that omission was half of a defect: the column was written double-encoded for
 * this service's whole life and no read path touched it, so nothing in the estate — not a test, not
 * an operator, not a dashboard — could observe that what came back out was not what went in. A
 * column nobody reads is a column nobody can find broken.
 *
 * No redaction happens here, on purpose and consistently with the rest of the service: scrubbing is
 * done ONCE, at ingest, before the insert (`toEventInput` -> `scrubValue`, `fromWire` ->
 * `scrubValue`), and `ingest.test.ts` proves the raw column carries no credential. Redacting again
 * at read would imply the stored bytes are dirty, which is the assumption this service is built to
 * refuse — a secret that reached the disk is already leaked, and a render-time mask only hides it
 * from the one caller polite enough to use the API.
 */
const EVENT_SELECT = `
  id::text as id, ts, service, source, severity, msg, request_id, trace_id, span_id,
  route, status_code, latency_ms, err_type, fingerprint, attributes
`

/** A safe request id: the runtime emits 16 chars of Crockford base32, but callers paste freely. */
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/

/** Every event for a request id, most recent first. The workflow the service exists to serve. */
export async function eventsByRequestId(sql: Sql, requestId: string, limit = 200): Promise<readonly EventRow[]> {
  if (!REQUEST_ID.test(requestId)) return []
  return (await sql.unsafe(
    `select ${EVENT_SELECT} from events where request_id = $1 order by ts desc limit $2`,
    [requestId, limit],
  )) as unknown as EventRow[]
}

/**
 * The trace id a request id maps to, or null.
 *
 * The most recent non-null trace among the request's events — a request produces many log lines and
 * they share one trace, so any of them answers, and the newest is the one whose link is freshest.
 */
export async function traceForRequestId(sql: Sql, requestId: string): Promise<string | null> {
  if (!REQUEST_ID.test(requestId)) return null
  const rows = (await sql.unsafe(
    `select trace_id from events
      where request_id = $1 and trace_id is not null
      order by ts desc limit 1`,
    [requestId],
  )) as unknown as Array<{ trace_id: string | null }>
  return rows[0]?.trace_id ?? null
}

/** Turn a trace id into a link, if the deploy configured a template. Otherwise no link. */
export function traceUrl(template: string, traceId: string | null): string | null {
  if (!template || traceId === null) return null
  return template.includes('{traceId}') ? template.replace('{traceId}', traceId) : `${template}${traceId}`
}

/** A bounded, filtered event list for the triage view. */
export async function listEvents(
  sql: Sql,
  filter: { service?: string; severity?: string; traceId?: string; limit?: number },
): Promise<readonly EventRow[]> {
  const clauses: string[] = []
  const params: unknown[] = []
  if (filter.service) {
    params.push(filter.service)
    clauses.push(`service = $${params.length}`)
  }
  if (filter.severity) {
    params.push(filter.severity)
    clauses.push(`severity = $${params.length}`)
  }
  if (filter.traceId && /^[0-9a-f]{32}$/.test(filter.traceId)) {
    params.push(filter.traceId)
    clauses.push(`trace_id = $${params.length}`)
  }
  params.push(Math.min(Math.max(filter.limit ?? 100, 1), 1000))
  const where = clauses.length ? `where ${clauses.join(' and ')}` : ''
  return (await sql.unsafe(
    `select ${EVENT_SELECT} from events ${where} order by ts desc limit $${params.length}`,
    params,
  )) as unknown as EventRow[]
}

/* ------------------------------------------------------------------ the browser samples */

export interface RumRow {
  readonly id: string
  readonly ts: Date
  readonly app: string
  readonly kind: string
  readonly route: string | null
  readonly value_ms: number | null
  readonly status_code: number | null
  readonly request_id: string | null
  readonly trace_id: string | null
  readonly session: string | null
  readonly attributes: Record<string, unknown>
}

/**
 * The browser samples, most recent first.
 *
 * `rum_samples` was WRITE-ONLY: inserted by the sink, deleted by retention, and selected by nothing
 * — so a browser error could be stored perfectly and still be invisible to every human in the
 * estate. That is worse than not collecting it, because it looks like coverage.
 *
 * `attributes` is the point of the read, not a detail of it. A browser error's own MESSAGE lives
 * there — `obs.ts` puts `type`, `message`, `stack`, `url`, `release` and `context` in the bag,
 * because `rum_samples` has no column for any of them — so a triage view without the bag shows an
 * operator that something called `error` happened on `/dashboard` and nothing whatsoever about
 * what it was. Same redaction reasoning as `EVENT_SELECT`: scrubbed once, at ingest.
 *
 * **Still no identity.** There is no `user_id` column to select, `session` is a per-tab random
 * string that dies with the tab, and the rows expire at thirty days. Exposing this read changes
 * none of that.
 */
export async function listRumSamples(
  sql: Sql,
  filter: { app?: string; kind?: string; session?: string; limit?: number },
): Promise<readonly RumRow[]> {
  const clauses: string[] = []
  const params: unknown[] = []
  for (const [column, value] of [
    ['app', filter.app],
    ['kind', filter.kind],
    ['session', filter.session],
  ] as const) {
    if (!value) continue
    params.push(value)
    clauses.push(`${column} = $${params.length}`)
  }
  params.push(Math.min(Math.max(filter.limit ?? 100, 1), 1000))
  const where = clauses.length ? `where ${clauses.join(' and ')}` : ''
  return (await sql.unsafe(
    `select id::text as id, ts, app, kind, route, value_ms, status_code, request_id, trace_id,
            session, attributes
       from rum_samples ${where} order by ts desc limit $${params.length}`,
    params,
  )) as unknown as RumRow[]
}
