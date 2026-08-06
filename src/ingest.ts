/**
 * The persistence path: a decoded OTLP record becomes an `events` row and, if it is a fault, an
 * `issues` upsert. This is the seam `otlp.ts → scrub.ts → fingerprint.ts → issues.ts` is wired at.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **SCRUBBING HAPPENS HERE, BEFORE THE INSERT, AND THAT IS THE WHOLE POINT.**
 *
 * The frozen service persists every credential any service in the estate ever wrote to a log line
 * (`stack/infra/lantern/src/sanitise.js` strips NUL bytes and clamps numbers and does nothing
 * else). Here every free-text field and the whole attribute tree pass through `scrub.ts` before a
 * single value is bound to a statement — there is exactly one way to not store a secret, and it is
 * to not store it. `msg`, `err_message` and `err_stack` are scrubbed; `attributes` is walked by
 * `scrubValue`, which also drops any value whose KEY is sensitive whatever its type.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **status_code is clamped here and refused at the column.** `events_status_code_range` (migration
 * 2) refuses anything outside 0..999, and an arbitrary JSON number reaching an INTEGER column
 * aborts the whole batch insert with 22003 — the defect the frozen `sanitise.js` records.
 * Clamping is the behaviour; the CHECK is the guarantee.
 */

import type { Sql } from '@cloudsforge/db'
import type { Limits } from './env.ts'
import type { OtlpRecord } from './otlp.ts'
import { severityOf } from './otlp.ts'
import { scrubString, scrubValue, type SecretKind } from './scrub.ts'
import { fingerprint, type Groupable } from './fingerprint.ts'
import { issueFrom, upsertIssue } from './issues.ts'

export type Source = 'otlp' | 'client' | 'docker'

export interface EventInput {
  readonly ts: Date
  readonly service: string
  readonly source: Source
  readonly severity: string
  readonly severityNumber: number
  readonly msg: string
  readonly requestId: string | null
  readonly traceId: string | null
  readonly spanId: string | null
  readonly route: string | null
  readonly statusCode: number | null
  readonly latencyMs: number | null
  readonly errType: string | null
  readonly errMessage: string | null
  readonly errStack: string | null
  readonly attributes: Record<string, unknown>
  readonly fingerprint: string | null
}

export interface IngestOutcome {
  /** Rows written to `events`. */
  readonly stored: number
  /** Distinct issues upserted from those rows. */
  readonly issues: number
  /** Secrets removed by kind, summed across the batch. */
  readonly removed: ReadonlyMap<SecretKind, number>
  /** Events by severity, for the counter. */
  readonly bySeverity: ReadonlyMap<string, number>
}

const NANOS_PER_MILLI = 1_000_000n

/** OTLP time is nanoseconds; JS Date is milliseconds. A zero or absent time falls back to `now`. */
function timeOf(record: OtlpRecord, now: Date): Date {
  const nanos = record.timeUnixNano ?? record.observedTimeUnixNano
  if (nanos === null || nanos <= 0n) return now
  const millis = nanos / NANOS_PER_MILLI
  // A time the far side of the year-10000 boundary is a producer error, not data. Fall back rather
  // than hand the driver a value that serialises to an Invalid Date.
  if (millis > 8_640_000_000_000_000n || millis < -8_640_000_000_000_000n) return now
  return new Date(Number(millis))
}

function firstString(attrs: Record<string, unknown>, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = attrs[key]
    if (typeof value === 'string' && value.length > 0) return value
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  }
  return null
}

function firstNumber(attrs: Record<string, unknown>, ...keys: string[]): number | null {
  for (const key of keys) {
    const value = attrs[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string' && /^-?\d+(?:\.\d+)?$/.test(value)) return Number(value)
  }
  return null
}

/** Clamp to the INTEGER `status_code` column's CHECK. Out-of-range or non-integer becomes null. */
function clampStatus(value: number | null): number | null {
  if (value === null) return null
  const n = Math.trunc(value)
  return n >= 0 && n < 1000 ? n : null
}

function clampLatency(value: number | null): number | null {
  if (value === null) return null
  const n = Math.trunc(value)
  return n >= 0 ? n : null
}

/** A trace/span id already normalised by the decoder, or a re-validated one from an attribute. */
function hexOrNull(value: string | null, length: number): string | null {
  if (value === null) return null
  const lower = value.toLowerCase()
  if (lower.length !== length || !/^[0-9a-f]+$/.test(lower)) return null
  if (/^0+$/.test(lower)) return null
  return lower
}

/**
 * Turn one decoded record into an insertable row, scrubbing every free-text field and the whole
 * attribute tree on the way. Returns the row and the secrets removed from it.
 */
export function toEventInput(
  record: OtlpRecord,
  source: Source,
  limits: Limits,
  now: Date = new Date(),
): { input: EventInput; removed: Map<SecretKind, number> } {
  const removed = new Map<SecretKind, number>()

  // The body carries the message; an object body (the estate's structured logger) carries the
  // message and the error under known keys. Everything else on it folds into attributes.
  let msg = ''
  let bodyErrType: string | null = null
  let bodyErrMessage: string | null = null
  let bodyErrStack: string | null = null
  const bodyExtra: Record<string, unknown> = {}
  if (typeof record.body === 'string') {
    msg = record.body
  } else if (record.body !== null && typeof record.body === 'object' && !Array.isArray(record.body)) {
    const body = record.body as Record<string, unknown>
    msg = firstString(body, 'msg', 'message', 'body') ?? ''
    const err = body['err'] ?? body['error'] ?? body['exception']
    if (err !== null && typeof err === 'object' && !Array.isArray(err)) {
      const e = err as Record<string, unknown>
      bodyErrType = firstString(e, 'type', 'name', 'code')
      bodyErrMessage = firstString(e, 'message', 'msg')
      bodyErrStack = firstString(e, 'stack', 'stacktrace')
    }
    for (const [key, value] of Object.entries(body)) {
      if (key === 'msg' || key === 'message' || key === 'body' || key === 'err' || key === 'error' || key === 'exception') continue
      bodyExtra[key] = value
    }
  } else if (record.body !== null) {
    msg = String(record.body)
  }
  if (msg.length === 0) msg = '(no message)'

  const attrs = record.attributes
  const service = firstString(attrs, 'service.name', 'service', 'container.name') ?? 'unknown'
  const requestId = firstString(attrs, 'request.id', 'request_id', 'requestId', 'req.id', 'reqId')
  const route = firstString(attrs, 'http.route', 'http.target', 'route')
  const statusCode = clampStatus(
    firstNumber(attrs, 'http.status_code', 'http.response.status_code', 'status_code', 'statusCode'),
  )
  const latencyMs = clampLatency(
    firstNumber(attrs, 'duration_ms', 'http.server.duration', 'latency_ms', 'latencyMs'),
  )
  const errType = bodyErrType ?? firstString(attrs, 'exception.type', 'error.type', 'err.type')
  const rawErrMessage = bodyErrMessage ?? firstString(attrs, 'exception.message', 'error.message', 'err.message')
  const rawErrStack = bodyErrStack ?? firstString(attrs, 'exception.stacktrace', 'error.stack', 'err.stack')

  // Scrub the free text. The error text and stack are exactly where a credential printed into a
  // sentence (`upstream refused: Authorization: Bearer eyJ…`) hides from the collector's
  // key-based redaction.
  const cleanMsg = merge(removed, scrubString(msg)).slice(0, limits.maxStringBytes)
  const cleanErrMessage = rawErrMessage === null ? null : merge(removed, scrubString(rawErrMessage))
  const cleanErrStack = rawErrStack === null ? null : merge(removed, scrubString(rawErrStack))

  // The attribute tree, minus the fields promoted to columns, scrubbed whole.
  const remaining: Record<string, unknown> = { ...bodyExtra }
  for (const [key, value] of Object.entries(attrs)) {
    if (PROMOTED_KEYS.has(key)) continue
    remaining[key] = value
  }
  const scrubbed = scrubValue(remaining, removed) as Record<string, unknown>

  const input: EventInput = {
    ts: timeOf(record, now),
    service,
    source,
    severity: severityOf(record.severityNumber, record.severityText),
    severityNumber: record.severityNumber,
    msg: cleanMsg,
    requestId,
    traceId: hexOrNull(record.traceId, 32),
    spanId: hexOrNull(record.spanId, 16),
    route,
    statusCode,
    latencyMs,
    errType,
    errMessage: cleanErrMessage,
    errStack: cleanErrStack,
    attributes: scrubbed,
    fingerprint: null,
  }

  const groupable = groupableOf(input)
  return { input: { ...input, fingerprint: fingerprint(groupable) }, removed }
}

const PROMOTED_KEYS = new Set([
  'service.name',
  'service',
  'container.name',
  'request.id',
  'request_id',
  'requestId',
  'req.id',
  'reqId',
  'http.route',
  'http.target',
  'route',
  'http.status_code',
  'http.response.status_code',
  'status_code',
  'statusCode',
  'duration_ms',
  'http.server.duration',
  'latency_ms',
  'latencyMs',
  'exception.type',
  'error.type',
  'err.type',
  'exception.message',
  'error.message',
  'err.message',
  'exception.stacktrace',
  'error.stack',
  'err.stack',
])

function merge(into: Map<SecretKind, number>, result: { value: string; removed: ReadonlyMap<SecretKind, number> }): string {
  for (const [kind, count] of result.removed) into.set(kind, (into.get(kind) ?? 0) + count)
  return result.value
}

/** The narrow view `fingerprint.ts` groups on, projected from a stored row. */
export function groupableOf(input: EventInput): Groupable {
  return {
    service: input.service,
    severity: input.severity,
    msg: input.msg,
    source: input.source,
    statusCode: input.statusCode,
    errType: input.errType,
    errMessage: input.errMessage,
    errStack: input.errStack,
  }
}

const EVENT_COLUMNS = 17

/**
 * Persist a batch: one multi-row insert into `events`, then one issue upsert per distinct
 * fingerprint carrying the aggregated first/last/count for that group.
 *
 * A single statement rather than a row-per-insert loop: the collector's default batch is hundreds
 * of records, and a round trip each is how an ingest path becomes the bottleneck the frozen
 * service's per-flush statement was written to avoid.
 */
export async function ingestEvents(
  sql: Sql,
  inputs: readonly EventInput[],
  now: Date = new Date(),
): Promise<IngestOutcome> {
  const removed = new Map<SecretKind, number>()
  const bySeverity = new Map<string, number>()
  for (const input of inputs) bySeverity.set(input.severity, (bySeverity.get(input.severity) ?? 0) + 1)

  if (inputs.length === 0) return { stored: 0, issues: 0, removed, bySeverity }

  const params: unknown[] = []
  const tuples: string[] = []
  inputs.forEach((input, row) => {
    const base = row * EVENT_COLUMNS
    const holes = Array.from({ length: EVENT_COLUMNS }, (_unused, i) => `$${base + i + 1}`)
    // The final column, attributes, is bound as an OBJECT and cast to jsonb. Not `JSON.stringify`
    // of it: postgres.js serialises a bound object to JSON itself, so pre-stringifying makes the
    // column hold a JSON *string* — `jsonb_typeof` returns 'string' and `attributes->>'k'` is
    // null. The cast stays, because the inferred parameter type is json and the column is jsonb.
    holes[EVENT_COLUMNS - 1] = `${holes[EVENT_COLUMNS - 1]}::jsonb`
    tuples.push(`(${holes.join(',')})`)
    params.push(
      input.ts.toISOString(),
      input.service,
      input.source,
      input.severity,
      input.severityNumber,
      input.msg,
      input.requestId,
      input.traceId,
      input.spanId,
      input.route,
      input.statusCode,
      input.latencyMs,
      input.errType,
      input.errMessage,
      input.errStack,
      input.fingerprint,
      input.attributes ?? {},
    )
  })

  await sql.unsafe(
    `insert into events
       (ts, service, source, severity, severity_number, msg, request_id, trace_id, span_id,
        route, status_code, latency_ms, err_type, err_message, err_stack, fingerprint, attributes)
     values ${tuples.join(',')}`,
    params,
  )

  // Aggregate the faults by fingerprint, so a thousand occurrences of one broken deploy are one
  // issue with `events = 1000` rather than a thousand upserts fighting over one row.
  interface Agg {
    representative: EventInput
    first: Date
    last: Date
    count: number
    firstTraceId: string | null
  }
  const groups = new Map<string, Agg>()
  for (const input of inputs) {
    if (input.fingerprint === null) continue
    const existing = groups.get(input.fingerprint)
    if (!existing) {
      groups.set(input.fingerprint, {
        representative: input,
        first: input.ts,
        last: input.ts,
        count: 1,
        firstTraceId: input.traceId,
      })
      continue
    }
    existing.count += 1
    if (input.ts < existing.first) {
      existing.first = input.ts
      existing.firstTraceId = input.traceId
      existing.representative = input
    }
    if (input.ts > existing.last) existing.last = input.ts
  }

  for (const [fp, agg] of groups) {
    await upsertIssue(
      sql,
      issueFrom(groupableOf(agg.representative), fp, agg.first, agg.last, agg.count, agg.firstTraceId),
    )
  }

  // `removed` is empty here on purpose: the inputs are already scrubbed, and the counts were
  // tallied by `toEventInput`. The `ingest` wrapper is what carries them through to the caller.
  return { stored: inputs.length, issues: groups.size, removed, bySeverity }
}

/**
 * Decode-to-persist for one batch: scrub each record, then store the batch.
 *
 * This is the function the OTLP route and the RUM error path call. It is the only place that both
 * maps records and writes them, so the secret counts accumulated during mapping are guaranteed to
 * reach the metric.
 */
export async function ingest(
  sql: Sql,
  records: readonly OtlpRecord[],
  source: Source,
  limits: Limits,
  now: Date = new Date(),
): Promise<IngestOutcome> {
  const removed = new Map<SecretKind, number>()
  const inputs = records.map((record) => {
    const mapped = toEventInput(record, source, limits, now)
    for (const [kind, count] of mapped.removed) removed.set(kind, (removed.get(kind) ?? 0) + count)
    return mapped.input
  })
  const outcome = await ingestEvents(sql, inputs, now)
  return { ...outcome, removed }
}
