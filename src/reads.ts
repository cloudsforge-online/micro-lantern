/**
 * The read paths: the request-id lookup that is this service's primary human workflow, the event
 * and issue lists, and the once-per-scrape gauge refresh.
 *
 * 13-operational-model.md:73-78 — "a user quotes an id from an error screen and an operator pastes
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
}

const EVENT_SELECT = `
  id::text as id, ts, service, source, severity, msg, request_id, trace_id, span_id,
  route, status_code, latency_ms, err_type, fingerprint
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
