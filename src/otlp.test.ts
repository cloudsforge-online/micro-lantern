/**
 * The hostile-input boundary. Protobuf and JSON decode, and every limit that REFUSES rather than
 * repairs — because a truncated length-delimited message is a different message, and an ingest
 * surface that truncates is one an attacker can steer.
 *
 * The protobuf encoder below is a test fixture, not shipped code: the smallest thing that can
 * produce a real `ExportLogsServiceRequest` so the hand-written decoder is exercised against bytes
 * it did not also generate.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  IngestError,
  clampString,
  decodeExport,
  decodeJson,
  decodeProtobuf,
  severityOf,
} from './otlp.ts'
import type { Limits } from './env.ts'

const LIMITS: Limits = {
  maxBodyBytes: 4 * 1024 * 1024,
  maxRecords: 100,
  maxAttributes: 32,
  maxDepth: 6,
  maxStringBytes: 8_192,
}

/* ------------------------------------------------------------------ a tiny protobuf encoder */

function varint(value: number | bigint): Buffer {
  let v = BigInt(value)
  const bytes: number[] = []
  do {
    let b = Number(v & 0x7fn)
    v >>= 7n
    if (v > 0n) b |= 0x80
    bytes.push(b)
  } while (v > 0n)
  return Buffer.from(bytes)
}
const tag = (field: number, wire: number): Buffer => varint((field << 3) | wire)
const lenDelim = (field: number, buf: Buffer): Buffer => Buffer.concat([tag(field, 2), varint(buf.length), buf])
const stringField = (field: number, s: string): Buffer => lenDelim(field, Buffer.from(s, 'utf8'))
const varintField = (field: number, n: number): Buffer => Buffer.concat([tag(field, 0), varint(n)])
function fixed64Field(field: number, n: bigint): Buffer {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64LE(n)
  return Buffer.concat([tag(field, 1), buf])
}

// AnyValue bodies.
const anyString = (s: string): Buffer => stringField(1, s)
const anyInt = (n: number): Buffer => varintField(3, n)
function anyKvlist(pairs: Array<{ key: string; value: Buffer }>): Buffer {
  const values = Buffer.concat(pairs.map((p) => lenDelim(1, keyValue(p.key, p.value))))
  return lenDelim(6, values)
}
// KeyValue: key at 1, value (AnyValue) at 2.
const keyValue = (key: string, valueBody: Buffer): Buffer =>
  Buffer.concat([stringField(1, key), lenDelim(2, valueBody)])

interface WireRecord {
  severityNumber?: number
  severityText?: string
  body?: Buffer
  attributes?: Array<{ key: string; value: Buffer }>
  traceId?: Buffer
  spanId?: Buffer
  timeUnixNano?: bigint
}

function logRecord(record: WireRecord): Buffer {
  const parts: Buffer[] = []
  if (record.timeUnixNano !== undefined) parts.push(fixed64Field(1, record.timeUnixNano))
  if (record.severityNumber !== undefined) parts.push(varintField(2, record.severityNumber))
  if (record.severityText !== undefined) parts.push(stringField(3, record.severityText))
  if (record.body !== undefined) parts.push(lenDelim(5, record.body))
  for (const attr of record.attributes ?? []) parts.push(lenDelim(6, keyValue(attr.key, attr.value)))
  if (record.traceId !== undefined) parts.push(lenDelim(9, record.traceId))
  if (record.spanId !== undefined) parts.push(lenDelim(10, record.spanId))
  return Buffer.concat(parts)
}

interface WireExport {
  resourceAttributes?: Array<{ key: string; value: Buffer }>
  scopeAttributes?: Array<{ key: string; value: Buffer }>
  records: WireRecord[]
}

function buildExport(input: WireExport): Buffer {
  const logRecords = Buffer.concat(input.records.map((r) => lenDelim(2, logRecord(r))))
  const scope = Buffer.concat((input.scopeAttributes ?? []).map((a) => lenDelim(3, keyValue(a.key, a.value))))
  const scopeLogs = Buffer.concat([
    ...(scope.length > 0 ? [lenDelim(1, scope)] : []),
    logRecords,
  ])
  const resource = Buffer.concat((input.resourceAttributes ?? []).map((a) => lenDelim(1, keyValue(a.key, a.value))))
  const resourceLogs = Buffer.concat([
    ...(resource.length > 0 ? [lenDelim(1, resource)] : []),
    lenDelim(2, scopeLogs),
  ])
  return lenDelim(1, resourceLogs)
}

/* ------------------------------------------------------------------ protobuf decode */

describe('decodeProtobuf', () => {
  it('decodes a single record with service, severity and a string body', () => {
    const body = buildExport({
      resourceAttributes: [{ key: 'service.name', value: anyString('ledger') }],
      records: [{ severityNumber: 17, severityText: 'ERROR', body: anyString('boom') }],
    })
    const result = decodeProtobuf(body, LIMITS)
    assert.equal(result.records.length, 1)
    const record = result.records[0]!
    assert.equal(record.body, 'boom')
    assert.equal(record.severityNumber, 17)
    assert.equal(record.attributes['service.name'], 'ledger')
  })

  it('merges attributes with record winning over scope over resource', () => {
    const body = buildExport({
      resourceAttributes: [{ key: 'k', value: anyString('resource') }],
      scopeAttributes: [{ key: 'k', value: anyString('scope') }],
      records: [{ body: anyString('x'), attributes: [{ key: 'k', value: anyString('record') }] }],
    })
    assert.equal(decodeProtobuf(body, LIMITS).records[0]!.attributes['k'], 'record')
  })

  it('decodes a well-formed trace id and span id to lowercase hex', () => {
    const traceId = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
    const spanId = Buffer.from('0011223344556677', 'hex')
    const body = buildExport({ records: [{ body: anyString('x'), traceId, spanId }] })
    const record = decodeProtobuf(body, LIMITS).records[0]!
    assert.equal(record.traceId, '00112233445566778899aabbccddeeff')
    assert.equal(record.spanId, '0011223344556677')
  })

  it('drops an all-zero trace id — the OTLP encoding of "no trace"', () => {
    const body = buildExport({ records: [{ body: anyString('x'), traceId: Buffer.alloc(16) }] })
    assert.equal(decodeProtobuf(body, LIMITS).records[0]!.traceId, null)
  })

  it('drops a wrong-length trace id rather than storing a dead link', () => {
    const body = buildExport({ records: [{ body: anyString('x'), traceId: Buffer.alloc(8) }] })
    assert.equal(decodeProtobuf(body, LIMITS).records[0]!.traceId, null)
  })

  it('decodes a kvlist body into a nested object', () => {
    const body = buildExport({
      records: [{ body: anyKvlist([{ key: 'msg', value: anyString('hi') }, { key: 'n', value: anyInt(5) }]) }],
    })
    const decoded = decodeProtobuf(body, LIMITS).records[0]!.body as Record<string, unknown>
    assert.equal(decoded['msg'], 'hi')
    assert.equal(decoded['n'], 5)
  })
})

describe('the limits refuse rather than repair', () => {
  it('rejects a batch above maxRecords as a whole-request 400', () => {
    const records = Array.from({ length: LIMITS.maxRecords + 1 }, () => ({ body: anyString('x') }))
    assert.throws(() => decodeProtobuf(buildExport({ records }), LIMITS), (err: unknown) => {
      assert.ok(err instanceof IngestError)
      assert.equal(err.status, 400)
      assert.equal(err.code, 'too_many_records')
      return true
    })
  })

  it('refuses ONE record over the attribute limit, keeping the batch', () => {
    const many = Array.from({ length: LIMITS.maxAttributes + 1 }, (_u, i) => ({ key: `k${i}`, value: anyString('v') }))
    const body = buildExport({
      records: [{ body: anyString('kept') }, { body: anyString('dropped'), attributes: many }],
    })
    const result = decodeProtobuf(body, LIMITS)
    assert.equal(result.records.length, 1)
    assert.equal(result.records[0]!.body, 'kept')
    assert.equal(result.rejected.get('attributes'), 1)
  })

  it('refuses ONE record nested past maxDepth, keeping the batch', () => {
    // Build a kvlist nested one deeper than the limit allows.
    let value = anyString('deep')
    for (let i = 0; i <= LIMITS.maxDepth + 1; i++) value = anyKvlist([{ key: 'n', value }])
    const body = buildExport({ records: [{ body: anyString('kept') }, { body: value }] })
    const result = decodeProtobuf(body, LIMITS)
    assert.equal(result.rejected.get('depth'), 1)
    assert.equal(result.records.length, 1)
  })

  it('a body over the size limit is refused with 413 and nothing is read', () => {
    const tiny: Limits = { ...LIMITS, maxBodyBytes: 16 }
    const body = buildExport({ records: [{ body: anyString('x'.repeat(1000)) }] })
    assert.throws(() => decodeExport(body, 'application/x-protobuf', tiny), (err: unknown) => {
      assert.ok(err instanceof IngestError)
      assert.equal(err.status, 413)
      return true
    })
  })

  it('a length prefix past the end of the buffer is a 400, not an over-read', () => {
    // A submessage claiming more bytes than the body holds is the classic over-read.
    const bad = Buffer.concat([tag(1, 2), varint(1000), Buffer.from([0x01, 0x02])])
    assert.throws(() => decodeProtobuf(bad, LIMITS), IngestError)
  })

  it('a varint that never terminates is a 400', () => {
    const bad = Buffer.concat([tag(1, 2), varint(3), Buffer.from([0x80, 0x80, 0x80])])
    assert.throws(() => decodeProtobuf(bad, LIMITS), IngestError)
  })
})

describe('clampString clamps by BYTES, not code units', () => {
  it('leaves a short string alone', () => {
    assert.equal(clampString('hello', LIMITS), 'hello')
  })

  it('clamps a long ascii string to the byte ceiling', () => {
    const limits: Limits = { ...LIMITS, maxStringBytes: 10 }
    assert.equal(clampString('x'.repeat(50), limits).length, 10)
  })

  it('does not leave a broken half-character at the boundary', () => {
    const limits: Limits = { ...LIMITS, maxStringBytes: 5 }
    // Four-byte emoji: a naive code-unit slice would cut one in half.
    const out = clampString('😀😀😀', limits)
    assert.ok(!out.endsWith('�'))
    assert.ok(Buffer.byteLength(out, 'utf8') <= 5)
  })
})

describe('severityOf maps the OTLP number to the vocabulary, never to error by accident', () => {
  const table: Array<[number, string]> = [
    [1, 'trace'], [5, 'debug'], [9, 'info'], [13, 'warn'], [17, 'error'], [21, 'fatal'], [24, 'fatal'],
  ]
  for (const [num, word] of table) {
    it(`${num} → ${word}`, () => assert.equal(severityOf(num, ''), word))
  }

  it('an unset (zero) severity number becomes info, NOT error', () => {
    assert.equal(severityOf(0, ''), 'info')
  })

  it('falls back to the text when the number is unset', () => {
    assert.equal(severityOf(0, 'ERROR'), 'error')
    assert.equal(severityOf(0, 'critical'), 'fatal')
    assert.equal(severityOf(0, 'warning'), 'warn')
  })
})

/* ------------------------------------------------------------------ JSON decode */

describe('decodeJson accepts proto3 JSON in both spellings', () => {
  it('reads camelCase resourceLogs / logRecords', () => {
    const text = JSON.stringify({
      resourceLogs: [
        {
          resource: { attributes: [{ key: 'service.name', value: { stringValue: 'market' } }] },
          scopeLogs: [
            { logRecords: [{ severityNumber: 17, body: { stringValue: 'boom' }, traceId: '00112233445566778899aabbccddeeff' }] },
          ],
        },
      ],
    })
    const record = decodeJson(text, LIMITS).records[0]!
    assert.equal(record.attributes['service.name'], 'market')
    assert.equal(record.body, 'boom')
    assert.equal(record.traceId, '00112233445566778899aabbccddeeff')
  })

  it('reads snake_case resource_logs / log_records', () => {
    const text = JSON.stringify({
      resource_logs: [{ scope_logs: [{ log_records: [{ severity_number: 9, body: { stringValue: 'x' } }] }] }],
    })
    assert.equal(decodeJson(text, LIMITS).records[0]!.severityNumber, 9)
  })

  it('reads an int64 nanos time encoded as a STRING', () => {
    const text = JSON.stringify({
      resourceLogs: [{ scopeLogs: [{ logRecords: [{ timeUnixNano: '1735689600000000000', body: { stringValue: 'x' } }] }] }],
    })
    assert.equal(decodeJson(text, LIMITS).records[0]!.timeUnixNano, 1735689600000000000n)
  })

  it('reads a severity enum NAME', () => {
    const text = JSON.stringify({
      resourceLogs: [{ scopeLogs: [{ logRecords: [{ severityNumber: 'SEVERITY_NUMBER_WARN2', body: { stringValue: 'x' } }] }] }],
    })
    assert.equal(decodeJson(text, LIMITS).records[0]!.severityNumber, 14)
  })

  it('refuses a non-object body', () => {
    assert.throws(() => decodeJson('[]', LIMITS), IngestError)
    assert.throws(() => decodeJson('not json', LIMITS), IngestError)
  })
})

describe('decodeExport chooses by content type', () => {
  it('treats an absent content type as protobuf — the collector sends no type', () => {
    const body = buildExport({ records: [{ body: anyString('x') }] })
    assert.equal(decodeExport(body, '', LIMITS).records.length, 1)
  })

  it('answers 415 for an unsupported content type', () => {
    assert.throws(() => decodeExport(Buffer.from('{}'), 'text/xml', LIMITS), (err: unknown) => {
      assert.ok(err instanceof IngestError)
      assert.equal(err.status, 415)
      return true
    })
  })

  it('routes application/json to the JSON decoder', () => {
    const text = JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords: [{ body: { stringValue: 'j' } }] }] }] })
    assert.equal(decodeExport(Buffer.from(text), 'application/json; charset=utf-8', LIMITS).records[0]!.body, 'j')
  })
})
