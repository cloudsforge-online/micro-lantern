/**
 * OTLP/HTTP logs ingest. **The hostile-input boundary of this service.**
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PATH IS `POST /otlp/v1/logs`, AND THAT IS NOT A CHOICE.**
 *
 * `deploy/otel/collector.yaml` declares the exporter that feeds this service:
 *
 *     otlphttp/lantern:
 *       endpoint: ${env:LANTERN_OTLP_ENDPOINT}
 *
 * and `deploy/compose/env/otel-collector.env:24` and `deploy/Makefile:65` both set that variable to
 * `http://lantern:4010/otlp`. The collector's `otlphttp` exporter appends the signal path to its
 * configured endpoint, so the URL that actually arrives is `http://lantern:4010/otlp/v1/logs` on
 * port 4010. Both are matched here exactly rather than approximately.
 *
 * **AND THE BODY IS PROTOBUF, NOT JSON.** `otlphttp`'s `encoding` defaults to `proto`, and
 * `collector.yaml` does not set it. An implementation that accepted only `application/json` would
 * answer 415 to every single export the estate ever sent it — silently, because the exporter is
 * configured with `retry_on_failure: enabled: false` and a `sending_queue` that DROPS rather than
 * blocks (`collector.yaml`), by design, so that a Lantern outage cannot back-pressure the
 * log pipeline into Loki. Nothing would page. Lantern would simply be empty, and would look like a
 * service nobody had gotten round to using.
 *
 * So this decodes the protobuf wire format directly, by hand, with no dependency. The alternative
 * was to change the collector's config to `encoding: json` — cheaper to write and wrong: it would
 * have made a deployment repository match this service rather than this service match the
 * deployment, and `deploy/` is already built and already correct.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A LOG LINE IS THE MOST HOSTILE INPUT THIS ESTATE ACCEPTS.** Every other service's write
 * surface is typed by a contract and authenticated to a principal who owns the data. This one
 * accepts arbitrary bytes that some other service put in a string, which means it accepts whatever
 * an attacker could get any service in the estate to write into a log line — and on the RUM path
 * it accepts bytes straight from a browser.
 *
 * Four limits, and every one of them REFUSES rather than repairs:
 *
 *   * **Body size.** Past `maxBodyBytes` the request is 413 and nothing is read. Not truncated:
 *     truncating a length-delimited encoding does not produce a shorter message, it produces a
 *     DIFFERENT message. Cut a `bytes` field short and the remaining bytes are re-interpreted as
 *     the next field tag, so the record that lands in the database is a record nobody sent. That is
 *     a parser-differential, and it is the mechanism behind most of the interesting attacks on
 *     binary ingest.
 *   * **Record count.** A batch above `maxRecords` is refused whole.
 *   * **Attribute count.** A record above `maxAttributes` is refused — the record, not the batch,
 *     so one malformed line cannot cost five thousand honest ones. Refused records are reported in
 *     the OTLP `partial_success` field, which is the protocol's own answer to exactly this.
 *   * **Depth.** An attribute value nested past `maxDepth` refuses its record. Unbounded recursion
 *     over attacker-controlled nesting is a stack overflow, and a stack overflow in a Node process
 *     is a crash, not an exception.
 */

import type { Limits } from './env.ts'

/** A whole-request refusal. Carries the status the caller should answer with. */
export class IngestError extends Error {
  readonly status: number
  readonly code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'IngestError'
    this.status = status
    this.code = code
  }
}

/** Why one record was refused. Reported per-record, never as a whole-batch failure. */
export type RejectReason = 'attributes' | 'depth' | 'malformed'

export interface OtlpRecord {
  /** Nanoseconds since the epoch, as the wire carries it. Converted to a Date by the caller. */
  readonly timeUnixNano: bigint | null
  readonly observedTimeUnixNano: bigint | null
  readonly severityNumber: number
  readonly severityText: string
  /** The log body. A string in almost every case; an AnyValue tree is legal and is kept as one. */
  readonly body: unknown
  /** Resource, scope and record attributes merged, record winning. */
  readonly attributes: Readonly<Record<string, unknown>>
  readonly traceId: string | null
  readonly spanId: string | null
  readonly droppedAttributes: number
}

export interface DecodeResult {
  readonly records: readonly OtlpRecord[]
  /** Records refused by a structural limit, by reason. The OTLP partial-success payload. */
  readonly rejected: ReadonlyMap<RejectReason, number>
}

/* ------------------------------------------------------------------ severity */

/**
 * OTLP severity number to this service's own vocabulary.
 *
 * The ranges are from the OTLP specification: 1–4 TRACE, 5–8 DEBUG, 9–12 INFO, 13–16 WARN,
 * 17–20 ERROR, 21–24 FATAL. A number outside them, including the zero that an unset field decodes
 * to, becomes `info` — **never `error`**. Defaulting an unknown severity to error would let any
 * producer that forgot to set the field manufacture an issue per line, which is the grouping
 * explosion arriving through a different door.
 */
export function severityOf(number: number, text: string): string {
  if (number >= 21) return 'fatal'
  if (number >= 17) return 'error'
  if (number >= 13) return 'warn'
  if (number >= 9) return 'info'
  if (number >= 5) return 'debug'
  if (number >= 1) return 'trace'
  const lower = text.trim().toLowerCase()
  if (lower === 'fatal' || lower === 'critical' || lower === 'panic') return 'fatal'
  if (lower === 'error' || lower === 'err' || lower === 'severe') return 'error'
  if (lower === 'warn' || lower === 'warning') return 'warn'
  if (lower === 'debug') return 'debug'
  if (lower === 'trace') return 'trace'
  return 'info'
}

export const SEVERITIES: readonly string[] = Object.freeze([
  'trace',
  'debug',
  'info',
  'warn',
  'error',
  'fatal',
])

/* ------------------------------------------------------------------ protobuf */

const WIRE_VARINT = 0
const WIRE_FIXED64 = 1
const WIRE_BYTES = 2
const WIRE_FIXED32 = 5

/**
 * A protobuf wire-format reader over one buffer.
 *
 * Deliberately not a generated decoder. This reads five message types and it is easier to audit a
 * hundred lines than to audit a code generator's output plus the runtime it depends on — and a
 * dependency here would be a dependency in the process that parses attacker-controlled bytes.
 */
class Reader {
  readonly #buf: Buffer
  #pos: number
  readonly #end: number

  constructor(buf: Buffer, start = 0, end = buf.length) {
    this.#buf = buf
    this.#pos = start
    this.#end = end
  }

  get done(): boolean {
    return this.#pos >= this.#end
  }

  /** A varint, as a number. Refuses anything that cannot be represented exactly. */
  varint(): number {
    const value = this.varint64()
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new IngestError(400, 'malformed_protobuf', 'a varint exceeds the safe integer range')
    }
    return Number(value)
  }

  varint64(): bigint {
    let result = 0n
    let shift = 0n
    for (;;) {
      if (this.#pos >= this.#end) {
        throw new IngestError(400, 'malformed_protobuf', 'a varint runs past the end of the message')
      }
      // A varint is at most ten bytes. Without this bound a crafted run of 0x80 bytes is an
      // unbounded shift loop over the whole body.
      if (shift > 63n) {
        throw new IngestError(400, 'malformed_protobuf', 'a varint is longer than ten bytes')
      }
      const byte = this.#buf[this.#pos] as number
      this.#pos += 1
      result |= BigInt(byte & 0x7f) << shift
      if ((byte & 0x80) === 0) return result
      shift += 7n
    }
  }

  fixed64(): bigint {
    if (this.#pos + 8 > this.#end) {
      throw new IngestError(400, 'malformed_protobuf', 'a fixed64 runs past the end of the message')
    }
    const value = this.#buf.readBigUInt64LE(this.#pos)
    this.#pos += 8
    return value
  }

  fixed64Double(): number {
    if (this.#pos + 8 > this.#end) {
      throw new IngestError(400, 'malformed_protobuf', 'a double runs past the end of the message')
    }
    const value = this.#buf.readDoubleLE(this.#pos)
    this.#pos += 8
    return value
  }

  skipFixed32(): void {
    if (this.#pos + 4 > this.#end) {
      throw new IngestError(400, 'malformed_protobuf', 'a fixed32 runs past the end of the message')
    }
    this.#pos += 4
  }

  bytes(): Buffer {
    const length = this.varint()
    if (this.#pos + length > this.#end) {
      // The single most important bounds check in this file. A length prefix claiming more bytes
      // than the message holds is the classic way to read past a buffer, and Node would answer with
      // whatever happened to be adjacent in memory.
      throw new IngestError(400, 'malformed_protobuf', 'a length-delimited field runs past the end')
    }
    const out = this.#buf.subarray(this.#pos, this.#pos + length)
    this.#pos += length
    return out
  }

  /** A sub-reader over a length-delimited field, without copying. */
  sub(): Reader {
    const length = this.varint()
    if (this.#pos + length > this.#end) {
      throw new IngestError(400, 'malformed_protobuf', 'a submessage runs past the end')
    }
    const reader = new Reader(this.#buf, this.#pos, this.#pos + length)
    this.#pos += length
    return reader
  }

  /** Field number and wire type of the next field. */
  tag(): { field: number; wire: number } {
    const key = this.varint()
    const field = key >>> 3
    const wire = key & 7
    if (field === 0) {
      throw new IngestError(400, 'malformed_protobuf', 'field number 0 is not a valid field')
    }
    return { field, wire }
  }

  /** Consume a field this decoder does not read. Unknown fields are forward compatibility. */
  skip(wire: number): void {
    switch (wire) {
      case WIRE_VARINT:
        this.varint64()
        return
      case WIRE_FIXED64:
        this.fixed64()
        return
      case WIRE_BYTES:
        this.bytes()
        return
      case WIRE_FIXED32:
        this.skipFixed32()
        return
      default:
        // Wire types 3 and 4 are the deprecated group encoding, and 6/7 do not exist. Nothing in
        // OTLP emits them, so a message that carries one is not an OTLP message.
        throw new IngestError(400, 'malformed_protobuf', `unsupported wire type ${wire}`)
    }
  }
}

/** Decoded AnyValue, plus the depth it reached, so the caller can enforce a ceiling. */
function readAnyValue(reader: Reader, depth: number, limits: Limits): unknown {
  if (depth > limits.maxDepth) {
    throw new IngestError(400, 'too_deep', `an attribute value nests deeper than ${limits.maxDepth}`)
  }
  let value: unknown = null
  while (!reader.done) {
    const { field, wire } = reader.tag()
    switch (field) {
      case 1:
        if (wire !== WIRE_BYTES) throw wrongWire('string_value', wire)
        value = clampString(reader.bytes().toString('utf8'), limits)
        break
      case 2:
        if (wire !== WIRE_VARINT) throw wrongWire('bool_value', wire)
        value = reader.varint() !== 0
        break
      case 3: {
        if (wire !== WIRE_VARINT) throw wrongWire('int_value', wire)
        // int64 arrives as a zigzag-free two's-complement varint. Values outside the safe range
        // become strings rather than losing precision silently — a truncated id is worse than a
        // string, because it looks like a number that means something.
        const raw = reader.varint64()
        const signed = BigInt.asIntN(64, raw)
        value =
          signed >= BigInt(Number.MIN_SAFE_INTEGER) && signed <= BigInt(Number.MAX_SAFE_INTEGER)
            ? Number(signed)
            : signed.toString()
        break
      }
      case 4:
        if (wire !== WIRE_FIXED64) throw wrongWire('double_value', wire)
        value = reader.fixed64Double()
        break
      case 5: {
        if (wire !== WIRE_BYTES) throw wrongWire('array_value', wire)
        const array = reader.sub()
        const out: unknown[] = []
        while (!array.done) {
          const inner = array.tag()
          if (inner.field === 1 && inner.wire === WIRE_BYTES) {
            out.push(readAnyValue(array.sub(), depth + 1, limits))
          } else {
            array.skip(inner.wire)
          }
        }
        value = out
        break
      }
      case 6: {
        if (wire !== WIRE_BYTES) throw wrongWire('kvlist_value', wire)
        const list = reader.sub()
        const out: Record<string, unknown> = {}
        while (!list.done) {
          const inner = list.tag()
          if (inner.field === 1 && inner.wire === WIRE_BYTES) {
            const pair = readKeyValue(list.sub(), depth + 1, limits)
            out[pair.key] = pair.value
          } else {
            list.skip(inner.wire)
          }
        }
        value = out
        break
      }
      case 7:
        if (wire !== WIRE_BYTES) throw wrongWire('bytes_value', wire)
        // Rendered as base64 rather than kept as a Buffer: it is going into JSONB, and a Buffer
        // serialises to `{"type":"Buffer","data":[…]}`, which is neither readable nor small.
        value = reader.bytes().toString('base64').slice(0, limits.maxStringBytes)
        break
      default:
        reader.skip(wire)
    }
  }
  return value
}

function readKeyValue(reader: Reader, depth: number, limits: Limits): { key: string; value: unknown } {
  let key = ''
  let value: unknown = null
  while (!reader.done) {
    const { field, wire } = reader.tag()
    if (field === 1 && wire === WIRE_BYTES) key = clampString(reader.bytes().toString('utf8'), limits)
    else if (field === 2 && wire === WIRE_BYTES) value = readAnyValue(reader.sub(), depth + 1, limits)
    else reader.skip(wire)
  }
  return { key, value }
}

function wrongWire(field: string, wire: number): IngestError {
  return new IngestError(400, 'malformed_protobuf', `${field} arrived with wire type ${wire}`)
}

/**
 * Clamp one string to the configured ceiling, by BYTES rather than by characters.
 *
 * `String.prototype.slice` counts UTF-16 code units, so a limit expressed in bytes and enforced in
 * characters is no limit at all against a body of four-byte emoji. Slicing a Buffer can cut a
 * multi-byte sequence in half, so the tail is re-decoded and any resulting replacement character
 * at the boundary is dropped.
 */
export function clampString(value: string, limits: Limits): string {
  const buffer = Buffer.from(value, 'utf8')
  if (buffer.length <= limits.maxStringBytes) return value
  const cut = buffer.subarray(0, limits.maxStringBytes).toString('utf8')
  return cut.endsWith('�') ? cut.slice(0, -1) : cut
}

/* ------------------------------------------------------------------ the message tree */

interface Attributes {
  readonly entries: Record<string, unknown>
  readonly count: number
}

function readAttributes(reader: Reader, field: number, limits: Limits): Attributes {
  const entries: Record<string, unknown> = {}
  let count = 0
  while (!reader.done) {
    const tag = reader.tag()
    if (tag.field === field && tag.wire === WIRE_BYTES) {
      const pair = readKeyValue(reader.sub(), 1, limits)
      if (pair.key.length > 0) entries[pair.key] = pair.value
      count += 1
    } else {
      reader.skip(tag.wire)
    }
  }
  return { entries, count }
}

function readLogRecord(reader: Reader, limits: Limits): {
  record: Omit<OtlpRecord, 'attributes'>
  attributes: Record<string, unknown>
  attributeCount: number
} {
  let timeUnixNano: bigint | null = null
  let observedTimeUnixNano: bigint | null = null
  let severityNumber = 0
  let severityText = ''
  let body: unknown = null
  let traceId: string | null = null
  let spanId: string | null = null
  let droppedAttributes = 0
  const attributes: Record<string, unknown> = {}
  let attributeCount = 0

  while (!reader.done) {
    const { field, wire } = reader.tag()
    switch (field) {
      case 1:
        if (wire !== WIRE_FIXED64) throw wrongWire('time_unix_nano', wire)
        timeUnixNano = reader.fixed64()
        break
      case 2:
        if (wire !== WIRE_VARINT) throw wrongWire('severity_number', wire)
        severityNumber = reader.varint()
        break
      case 3:
        if (wire !== WIRE_BYTES) throw wrongWire('severity_text', wire)
        severityText = clampString(reader.bytes().toString('utf8'), limits)
        break
      case 5:
        if (wire !== WIRE_BYTES) throw wrongWire('body', wire)
        body = readAnyValue(reader.sub(), 1, limits)
        break
      case 6: {
        if (wire !== WIRE_BYTES) throw wrongWire('attributes', wire)
        const pair = readKeyValue(reader.sub(), 1, limits)
        if (pair.key.length > 0) attributes[pair.key] = pair.value
        attributeCount += 1
        break
      }
      case 7:
        if (wire !== WIRE_VARINT) throw wrongWire('dropped_attributes_count', wire)
        droppedAttributes = reader.varint()
        break
      case 8:
        if (wire !== WIRE_FIXED32) throw wrongWire('flags', wire)
        reader.skipFixed32()
        break
      case 9:
        if (wire !== WIRE_BYTES) throw wrongWire('trace_id', wire)
        traceId = hexOrNull(reader.bytes(), 16)
        break
      case 10:
        if (wire !== WIRE_BYTES) throw wrongWire('span_id', wire)
        spanId = hexOrNull(reader.bytes(), 8)
        break
      case 11:
        if (wire !== WIRE_FIXED64) throw wrongWire('observed_time_unix_nano', wire)
        observedTimeUnixNano = reader.fixed64()
        break
      default:
        reader.skip(wire)
    }
  }

  return {
    record: {
      timeUnixNano,
      observedTimeUnixNano,
      severityNumber,
      severityText,
      body,
      traceId,
      spanId,
      droppedAttributes,
    },
    attributes,
    attributeCount,
  }
}

/**
 * A trace or span id as lowercase hex, or null.
 *
 * An id of the wrong length is dropped rather than stored. The column carries a CHECK that it is
 * exactly 32 or 16 hex characters, so a short id would fail the INSERT and cost the whole batch —
 * and a wrong-length trace id joins to nothing in Tempo anyway.
 */
function hexOrNull(bytes: Buffer, expected: number): string | null {
  if (bytes.length !== expected) return null
  // An all-zero id is the OTLP encoding of "no trace", and storing it would make every unsampled
  // record appear to share one trace.
  if (bytes.every((byte) => byte === 0)) return null
  return bytes.toString('hex')
}

/** Decode `ExportLogsServiceRequest` from the protobuf wire format. */
export function decodeProtobuf(body: Buffer, limits: Limits): DecodeResult {
  const records: OtlpRecord[] = []
  const rejected = new Map<RejectReason, number>()
  const root = new Reader(body)

  while (!root.done) {
    const { field, wire } = root.tag()
    if (field !== 1 || wire !== WIRE_BYTES) {
      root.skip(wire)
      continue
    }
    const resourceLogs = root.sub()
    let resourceAttributes: Record<string, unknown> = {}
    let resourceCount = 0

    // ResourceLogs carries `resource` at 1 and repeated `scope_logs` at 2, and the wire format does
    // not promise field order. The resource is read on the first pass and applied to every scope
    // afterwards, so a producer that emits scope_logs first does not lose `service.name`.
    const scopes: Reader[] = []
    while (!resourceLogs.done) {
      const inner = resourceLogs.tag()
      if (inner.field === 1 && inner.wire === WIRE_BYTES) {
        const attributes = readAttributes(resourceLogs.sub(), 1, limits)
        resourceAttributes = attributes.entries
        resourceCount = attributes.count
      } else if (inner.field === 2 && inner.wire === WIRE_BYTES) {
        scopes.push(resourceLogs.sub())
      } else {
        resourceLogs.skip(inner.wire)
      }
    }

    for (const scopeLogs of scopes) {
      let scopeAttributes: Record<string, unknown> = {}
      let scopeCount = 0
      const logRecords: Reader[] = []
      while (!scopeLogs.done) {
        const inner = scopeLogs.tag()
        if (inner.field === 1 && inner.wire === WIRE_BYTES) {
          // InstrumentationScope: name 1, version 2, attributes 3.
          const scope = scopeLogs.sub()
          const attributes = readAttributes(scope, 3, limits)
          scopeAttributes = attributes.entries
          scopeCount = attributes.count
        } else if (inner.field === 2 && inner.wire === WIRE_BYTES) {
          logRecords.push(scopeLogs.sub())
        } else {
          scopeLogs.skip(inner.wire)
        }
      }

      for (const logRecord of logRecords) {
        if (records.length >= limits.maxRecords) {
          throw new IngestError(
            400,
            'too_many_records',
            `an export may carry at most ${limits.maxRecords} log records`,
          )
        }
        let decoded: ReturnType<typeof readLogRecord>
        try {
          decoded = readLogRecord(logRecord, limits)
        } catch (err) {
          // A depth violation refuses ONE record. Everything else is a malformed message and is a
          // whole-request failure: a body this decoder cannot parse is a body whose remaining
          // records cannot be trusted to be the records the sender meant.
          if (err instanceof IngestError && err.code === 'too_deep') {
            bumpReject(rejected, 'depth')
            continue
          }
          throw err
        }
        const total = decoded.attributeCount + resourceCount + scopeCount
        if (total > limits.maxAttributes) {
          bumpReject(rejected, 'attributes')
          continue
        }
        records.push({
          ...decoded.record,
          // Record attributes win over scope, scope over resource. The most specific writer is the
          // one closest to the line, and a resource-level `service.name` must never overwrite a
          // record that named its own.
          attributes: { ...resourceAttributes, ...scopeAttributes, ...decoded.attributes },
        })
      }
    }
  }

  return { records, rejected }
}

function bumpReject(into: Map<RejectReason, number>, reason: RejectReason): void {
  into.set(reason, (into.get(reason) ?? 0) + 1)
}

/* ------------------------------------------------------------------ OTLP/JSON */

/**
 * Proto3 JSON, which OTLP also allows and which the browser path uses.
 *
 * Both spellings of every field are accepted — `resourceLogs` and `resource_logs`. The
 * specification says lowerCamelCase is produced and either is accepted, and an ingest surface that
 * accepted only what it happened to test against is a surface that silently drops one producer.
 */
export function decodeJson(text: string, limits: Limits): DecodeResult {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new IngestError(400, 'malformed_json', 'the request body is not valid JSON')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new IngestError(400, 'malformed_json', 'the request body must be a JSON object')
  }

  const records: OtlpRecord[] = []
  const rejected = new Map<RejectReason, number>()
  const root = parsed as Record<string, unknown>

  for (const resourceLogs of arrayAt(root, 'resourceLogs', 'resource_logs')) {
    const resource = objectAt(resourceLogs, 'resource')
    const resourceAttributes = jsonAttributes(resource, limits)

    for (const scopeLogs of arrayAt(resourceLogs, 'scopeLogs', 'scope_logs')) {
      const scope = objectAt(scopeLogs, 'scope')
      const scopeAttributes = jsonAttributes(scope, limits)

      for (const raw of arrayAt(scopeLogs, 'logRecords', 'log_records')) {
        if (records.length >= limits.maxRecords) {
          throw new IngestError(
            400,
            'too_many_records',
            `an export may carry at most ${limits.maxRecords} log records`,
          )
        }
        const recordAttributes = jsonAttributes(raw, limits)
        const total =
          recordAttributes.count + resourceAttributes.count + scopeAttributes.count
        if (total > limits.maxAttributes) {
          bumpReject(rejected, 'attributes')
          continue
        }
        let body: unknown
        try {
          body = jsonAnyValue(raw['body'], 1, limits)
        } catch (err) {
          if (err instanceof IngestError && err.code === 'too_deep') {
            bumpReject(rejected, 'depth')
            continue
          }
          throw err
        }
        records.push({
          timeUnixNano: nanosAt(raw, 'timeUnixNano', 'time_unix_nano'),
          observedTimeUnixNano: nanosAt(raw, 'observedTimeUnixNano', 'observed_time_unix_nano'),
          severityNumber: severityNumberOf(raw),
          severityText: stringAt(raw, 'severityText', 'severity_text', limits),
          body,
          attributes: {
            ...resourceAttributes.entries,
            ...scopeAttributes.entries,
            ...recordAttributes.entries,
          },
          traceId: hexStringOrNull(stringAt(raw, 'traceId', 'trace_id', limits), 32),
          spanId: hexStringOrNull(stringAt(raw, 'spanId', 'span_id', limits), 16),
          droppedAttributes: 0,
        })
      }
    }
  }

  return { records, rejected }
}

function arrayAt(source: unknown, camel: string, snake: string): readonly Record<string, unknown>[] {
  if (typeof source !== 'object' || source === null) return []
  const value = (source as Record<string, unknown>)[camel] ?? (source as Record<string, unknown>)[snake]
  if (!Array.isArray(value)) return []
  return value.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  )
}

function objectAt(source: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = source[key]
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function stringAt(source: Record<string, unknown>, camel: string, snake: string, limits: Limits): string {
  const value = source[camel] ?? source[snake]
  return typeof value === 'string' ? clampString(value, limits) : ''
}

/**
 * `timeUnixNano` is an int64, and proto3 JSON encodes an int64 as a STRING. Producers emit both,
 * so both are read — and a value that is neither is null rather than `NaN`, which would become an
 * Invalid Date and make the driver throw a RangeError with no SQLSTATE. The frozen service records
 * that exact failure at `stack/infra/lantern/src/sanitise.js`.
 */
function nanosAt(source: Record<string, unknown>, camel: string, snake: string): bigint | null {
  const value = source[camel] ?? source[snake]
  if (typeof value === 'bigint') return value
  if (typeof value === 'number') return Number.isFinite(value) ? BigInt(Math.trunc(value)) : null
  if (typeof value === 'string' && /^\d{1,20}$/.test(value)) return BigInt(value)
  return null
}

function severityNumberOf(source: Record<string, unknown>): number {
  const value = source['severityNumber'] ?? source['severity_number']
  if (typeof value === 'number' && Number.isInteger(value)) return value
  if (typeof value === 'string') {
    // Proto3 JSON permits the enum's NAME: `SEVERITY_NUMBER_ERROR`, `SEVERITY_NUMBER_WARN2`.
    const match = /^SEVERITY_NUMBER_([A-Z]+)(\d?)$/.exec(value.trim())
    if (match) {
      const base = { TRACE: 1, DEBUG: 5, INFO: 9, WARN: 13, ERROR: 17, FATAL: 21 }[match[1] ?? '']
      if (base !== undefined) return base + (match[2] ? Number(match[2]) - 1 : 0)
    }
    if (/^\d+$/.test(value)) return Number(value)
  }
  return 0
}

function hexStringOrNull(value: string, length: number): string | null {
  const lower = value.toLowerCase()
  if (lower.length !== length || !/^[0-9a-f]+$/.test(lower)) return null
  if (/^0+$/.test(lower)) return null
  return lower
}

function jsonAttributes(source: Record<string, unknown>, limits: Limits): Attributes {
  const entries: Record<string, unknown> = {}
  let count = 0
  const list = source['attributes']
  if (!Array.isArray(list)) return { entries, count }
  for (const entry of list) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue
    const pair = entry as Record<string, unknown>
    const key = typeof pair['key'] === 'string' ? clampString(pair['key'], limits) : ''
    count += 1
    if (key.length === 0) continue
    entries[key] = jsonAnyValue(pair['value'], 1, limits)
  }
  return { entries, count }
}

/** Proto3 JSON AnyValue. A `{ stringValue: … }` wrapper, or a bare value from a lenient producer. */
function jsonAnyValue(value: unknown, depth: number, limits: Limits): unknown {
  if (depth > limits.maxDepth) {
    throw new IngestError(400, 'too_deep', `an attribute value nests deeper than ${limits.maxDepth}`)
  }
  if (value === null || value === undefined) return null
  if (typeof value === 'string') return clampString(value, limits)
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.map((entry) => jsonAnyValue(entry, depth + 1, limits))

  const object = value as Record<string, unknown>
  if ('stringValue' in object || 'string_value' in object) {
    const raw = object['stringValue'] ?? object['string_value']
    return typeof raw === 'string' ? clampString(raw, limits) : ''
  }
  if ('boolValue' in object || 'bool_value' in object) {
    return Boolean(object['boolValue'] ?? object['bool_value'])
  }
  if ('intValue' in object || 'int_value' in object) {
    const raw = object['intValue'] ?? object['int_value']
    if (typeof raw === 'number') return raw
    if (typeof raw === 'string' && /^-?\d+$/.test(raw)) {
      const asBigInt = BigInt(raw)
      return asBigInt >= BigInt(Number.MIN_SAFE_INTEGER) && asBigInt <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(asBigInt)
        : raw
    }
    return null
  }
  if ('doubleValue' in object || 'double_value' in object) {
    const raw = object['doubleValue'] ?? object['double_value']
    return typeof raw === 'number' ? raw : Number(raw)
  }
  if ('bytesValue' in object || 'bytes_value' in object) {
    const raw = object['bytesValue'] ?? object['bytes_value']
    return typeof raw === 'string' ? raw.slice(0, limits.maxStringBytes) : null
  }
  if ('arrayValue' in object || 'array_value' in object) {
    const raw = objectAt(object, 'arrayValue' in object ? 'arrayValue' : 'array_value')
    const values = raw['values']
    return Array.isArray(values) ? values.map((entry) => jsonAnyValue(entry, depth + 1, limits)) : []
  }
  if ('kvlistValue' in object || 'kvlist_value' in object) {
    const raw = objectAt(object, 'kvlistValue' in object ? 'kvlistValue' : 'kvlist_value')
    const out: Record<string, unknown> = {}
    const values = raw['values']
    if (Array.isArray(values)) {
      for (const entry of values) {
        if (typeof entry !== 'object' || entry === null) continue
        const pair = entry as Record<string, unknown>
        if (typeof pair['key'] !== 'string') continue
        out[clampString(pair['key'], limits)] = jsonAnyValue(pair['value'], depth + 1, limits)
      }
    }
    return out
  }

  // A plain object from a producer that did not wrap. Walked rather than dropped: the RUM sink
  // sends context objects this way and losing them would lose the reason the record was sent.
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(object)) {
    out[clampString(key, limits)] = jsonAnyValue(entry, depth + 1, limits)
  }
  return out
}

/* ------------------------------------------------------------------ the entry point */

export const PROTOBUF_CONTENT_TYPE = 'application/x-protobuf'
export const JSON_CONTENT_TYPE = 'application/json'

/**
 * Decode one export, choosing by `Content-Type`.
 *
 * An absent content type is treated as protobuf, because that is what the collector sends and a
 * proxy that strips headers must not silently empty this service.
 */
export function decodeExport(body: Buffer, contentType: string, limits: Limits): DecodeResult {
  if (body.length > limits.maxBodyBytes) {
    throw new IngestError(413, 'body_too_large', `the request body exceeds ${limits.maxBodyBytes} bytes`)
  }
  const type = contentType.split(';')[0]?.trim().toLowerCase() ?? ''
  if (type === JSON_CONTENT_TYPE) return decodeJson(body.toString('utf8'), limits)
  if (type === PROTOBUF_CONTENT_TYPE || type === 'application/protobuf' || type === '') {
    return decodeProtobuf(body, limits)
  }
  throw new IngestError(
    415,
    'unsupported_media_type',
    `content-type must be ${PROTOBUF_CONTENT_TYPE} or ${JSON_CONTENT_TYPE}`,
  )
}
