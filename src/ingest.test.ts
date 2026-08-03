/**
 * The persistence path, end to end against a real Postgres: a decoded record becomes an events row
 * and, if it is a fault, an issue — with every credential removed BEFORE the insert, and a thousand
 * noisy occurrences collapsing to one issue.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import type { Limits } from './env.ts'
import type { OtlpRecord } from './otlp.ts'
import { ingest, toEventInput } from './ingest.ts'
import { eventsByRequestId, traceForRequestId } from './reads.ts'
import { db, migrateTestDb, openDb, resetLantern, skip } from './testsupport.ts'

const LIMITS: Limits = {
  maxBodyBytes: 4 * 1024 * 1024,
  maxRecords: 5_000,
  maxAttributes: 128,
  maxDepth: 8,
  maxStringBytes: 8_192,
}

function rec(overrides: Partial<OtlpRecord> = {}): OtlpRecord {
  return {
    timeUnixNano: null,
    observedTimeUnixNano: null,
    severityNumber: 17,
    severityText: 'ERROR',
    body: 'something failed',
    attributes: { 'service.name': 'ledger' },
    traceId: null,
    spanId: null,
    droppedAttributes: 0,
    ...overrides,
  }
}

describe('ingest', { skip }, () => {
  let sql: postgres.Sql

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
  })
  beforeEach(async () => {
    await resetLantern(sql)
  })
  after(async () => {
    await sql.end({ timeout: 5 })
  })

  /* ---------------------------------------------------------------- the credential guarantee */

  describe('a planted credential is NOT present in the database after ingest', () => {
    // Every shape the remit names, planted in the message body, the error text, and the attributes.
    // `aws` is assembled from fragments so the contiguous key id never appears in source — the
    // secret-hygiene scan greps every non-example file for exactly that shape, and a test proving
    // the scrubber catches it must not itself be the thing the scanner flags.
    const SECRETS = {
      openai: 'sk-abcdEFGH1234ijklMNOPqrst',
      stripe: 'sk_live_abcdefgh12345678ijkl',
      github: 'ghp_ABCDEFGHIJ0123456789klmn',
      aws: 'AKIA' + 'IOSFODNN7EXAMPLE',
      bearer: 'abcdef0123456789ABCDEFghij',
      dsn: 'topSecretDbPassword99',
      cookie: 'sid=deadbeefcafebabe0110',
    }

    it('strips secrets from msg, err fields and attributes before they are stored', async () => {
      const record = rec({
        body: {
          msg: `charge failed with key=${SECRETS.stripe} and openai ${SECRETS.openai}`,
          err: {
            type: 'UpstreamError',
            message: `git clone failed: ${SECRETS.github}; Authorization: Bearer ${SECRETS.bearer}`,
            stack: `Error\n    at connect postgres://app:${SECRETS.dsn}@db:5432/app`,
          },
        },
        attributes: {
          'service.name': 'ledger',
          'aws.key': SECRETS.aws,
          authorization: `Bearer ${SECRETS.bearer}`,
          'set-cookie': `Set-Cookie: ${SECRETS.cookie}; Path=/`,
          password: SECRETS.dsn,
        },
      })

      const outcome = await ingest(db(sql), [record], 'otlp', LIMITS)
      assert.equal(outcome.stored, 1)
      assert.ok(outcome.removed.size > 0, 'expected secrets to have been removed')

      // Sweep EVERY text-bearing column and the jsonb, rendered to text, for any planted secret.
      const rows = (await sql`
        select coalesce(msg,'') || ' ' || coalesce(err_type,'') || ' ' || coalesce(err_message,'')
            || ' ' || coalesce(err_stack,'') || ' ' || attributes::text as blob
          from events
      `) as unknown as Array<{ blob: string }>
      const issueRows = (await sql`select title from issues`) as unknown as Array<{ title: string }>
      const haystack = rows.map((r) => r.blob).join('\n') + '\n' + issueRows.map((r) => r.title).join('\n')

      for (const [name, secret] of Object.entries(SECRETS)) {
        assert.doesNotMatch(haystack, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `secret "${name}" reached the database`)
      }
    })

    it('scrubs before persistence, not at render — the raw column carries no secret', async () => {
      await ingest(db(sql), [rec({ body: `token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaaabbbbcccc dddd` })], 'otlp', LIMITS)
      const rows = (await sql`select msg from events`) as unknown as Array<{ msg: string }>
      assert.match(rows[0]!.msg, /\[redacted:jwt\]/)
    })
  })

  /* ---------------------------------------------------------------- grouping */

  describe('grouping collapses many occurrences into one issue', () => {
    it('a thousand noisy occurrences of one fault are one issue with events = 1000', async () => {
      const records = Array.from({ length: 1000 }, (_unused, i) =>
        rec({
          body: {
            msg: `failed to load user ${uuid(i)} at 2026-07-31T14:${pad(i % 60)}:00.000Z req ${reqId(i)}`,
            err: { type: 'LoadError', message: 'not found', stack: 'Error\n    at src/ledger.ts:42:9' },
          },
        }),
      )
      const outcome = await ingest(db(sql), records, 'otlp', LIMITS)
      assert.equal(outcome.stored, 1000)
      assert.equal(outcome.issues, 1)

      const issues = (await sql`select fingerprint, events::int as events from issues`) as unknown as Array<{ fingerprint: string; events: number }>
      assert.equal(issues.length, 1)
      assert.equal(issues[0]!.events, 1000)
    })

    it('accumulates the running total across batches', async () => {
      const one = rec({ body: { msg: 'boom', err: { type: 'E', message: 'x', stack: 'Error\n    at src/a.ts:1:1' } } })
      await ingest(db(sql), [one, one], 'otlp', LIMITS)
      await ingest(db(sql), [one], 'otlp', LIMITS)
      const issues = (await sql`select events::int as events from issues`) as unknown as Array<{ events: number }>
      assert.equal(issues[0]!.events, 3)
    })

    it('does not create an issue for a non-fault', async () => {
      await ingest(db(sql), [rec({ severityNumber: 9, severityText: 'INFO', body: 'just fyi' })], 'otlp', LIMITS)
      const issues = (await sql`select count(*)::int as n from issues`) as unknown as Array<{ n: number }>
      assert.equal(issues[0]!.n, 0)
      const events = (await sql`select count(*)::int as n from events`) as unknown as Array<{ n: number }>
      assert.equal(events[0]!.n, 1)
    })
  })

  /* ---------------------------------------------------------------- request-id lookup */

  describe('the request-id lookup finds the right trace', () => {
    it('maps a request id to the trace of its events', async () => {
      const traceId = '00112233445566778899aabbccddeeff'
      await ingest(
        db(sql),
        [rec({ body: 'handled', attributes: { 'service.name': 'market', 'request.id': 'k3m9p2q7r4s8t1v6' }, traceId })],
        'otlp',
        LIMITS,
      )
      // A decoy under a different request id must not be returned.
      await ingest(
        db(sql),
        [rec({ body: 'other', attributes: { 'service.name': 'market', 'request.id': 'zzzzzzzzzzzzzzzz' }, traceId: 'ffffffffffffffffffffffffffffffff' })],
        'otlp',
        LIMITS,
      )

      const found = await traceForRequestId(db(sql), 'k3m9p2q7r4s8t1v6')
      assert.equal(found, traceId)

      const events = await eventsByRequestId(db(sql), 'k3m9p2q7r4s8t1v6')
      assert.equal(events.length, 1)
      assert.equal(events[0]!.trace_id, traceId)
      assert.equal(events[0]!.request_id, 'k3m9p2q7r4s8t1v6')
    })

    it('returns nothing for an unknown request id', async () => {
      assert.equal(await traceForRequestId(db(sql), 'nope1nope2nope3n'), null)
      assert.equal((await eventsByRequestId(db(sql), 'nope1nope2nope3n')).length, 0)
    })
  })

  /* ---------------------------------------------------------------- the status ladder */

  describe('a resolved issue that happens again regresses rather than staying green', () => {
    it('moves resolved → regressed and stamps regressed_at when a later occurrence arrives', async () => {
      // Both occurrences land at ~now (no explicit time); the resolve is stamped an hour in the
      // past, so the later occurrence's `last_seen` is genuinely after `resolved_at`.
      const fault = rec({ body: { msg: 'boom', err: { type: 'E', message: 'x', stack: 'Error\n    at src/a.ts:1:1' } } })
      await ingest(db(sql), [fault], 'otlp', LIMITS)

      // An operator resolved it an hour ago.
      await sql`update issues set status = 'resolved', resolved_at = now() - interval '1 hour', resolved_by = 'op'`

      // It happens again, now — after the resolve.
      await ingest(db(sql), [fault], 'otlp', LIMITS)

      const rows = (await sql`select status, regressed_at from issues`) as unknown as Array<{ status: string; regressed_at: Date | null }>
      assert.equal(rows[0]!.status, 'regressed')
      assert.ok(rows[0]!.regressed_at instanceof Date)
    })
  })

  /* ---------------------------------------------------------------- column mapping */

  describe('the record maps onto the columns', () => {
    it('clamps an out-of-range status code to null rather than aborting the batch', () => {
      const { input } = toEventInput(rec({ attributes: { 'service.name': 's', 'http.status_code': 1e30 } }), 'otlp', LIMITS)
      assert.equal(input.statusCode, null)
    })

    it('promotes service.name, request id, route and status out of the attribute bag', () => {
      const { input } = toEventInput(
        rec({ attributes: { 'service.name': 'pay', 'request.id': 'r1', 'http.route': '/charge', 'http.status_code': 503 } }),
        'otlp',
        LIMITS,
      )
      assert.equal(input.service, 'pay')
      assert.equal(input.requestId, 'r1')
      assert.equal(input.route, '/charge')
      assert.equal(input.statusCode, 503)
      // The promoted keys are not duplicated back into the stored attribute bag.
      assert.ok(!('service.name' in input.attributes))
      assert.ok(!('http.status_code' in input.attributes))
    })
  })

  /* ---------------------------------------------------------------- the stored jsonb column */

  /**
   * `events.attributes` carried the SAME double-encode defect as `rum_samples.attributes`:
   * `JSON.stringify` in `ingestEvents` on top of postgres.js's own JSON serialisation, so the
   * column held a JSON string and `jsonb_typeof` answered 'string'.
   *
   * The two assertions above are on `input.attributes` — the object BEFORE the insert — and the
   * credential sweep further up reads `attributes::text`, which contains the same substrings under
   * either encoding and therefore passes either way. Neither could see the fault. These read the
   * column back with jsonb operators, which is the only thing that can.
   */
  describe('the attribute bag is stored as jsonb, not as a string containing jsonb', () => {
    it('stores an object whose keys the database can extract', async () => {
      await ingest(
        db(sql),
        [rec({ attributes: { 'service.name': 'pay', 'db.system': 'postgres', retries: 3 } })],
        'otlp',
        LIMITS,
      )
      const rows = (await sql`
        select jsonb_typeof(attributes)     as t,
               attributes->>'db.system'     as db_system,
               attributes->>'retries'       as retries,
               coalesce((select array_agg(k order by k) from jsonb_object_keys(attributes) k), array[]::text[]) as keys
          from events
      `) as unknown as Array<{ t: string; db_system: string | null; retries: string | null; keys: string[] }>
      assert.equal(rows[0]!.t, 'object')
      assert.equal(rows[0]!.db_system, 'postgres')
      assert.equal(rows[0]!.retries, '3')
      // `service.name` was promoted to a column, so it must NOT be here — which is only checkable
      // at all once the column is a walkable object.
      assert.deepEqual(rows[0]!.keys, ['db.system', 'retries'])
    })

    it('supports the containment operator an operator would actually filter with', async () => {
      await ingest(db(sql), [rec({ attributes: { 'service.name': 'pay', tier: 'gold' } })], 'otlp', LIMITS)
      // `@>` on a JSON string is not an error — it simply never matches, which is how a broken
      // encoding turns a filter into a permanently empty result set rather than a failure.
      const hit = (await sql`select count(*)::int as n from events where attributes @> '{"tier":"gold"}'::jsonb`) as unknown as Array<{ n: number }>
      assert.equal(hit[0]!.n, 1)
    })
  })
})

/* ------------------------------------------------------------------ noise generators */

function pad(n: number): string {
  return n.toString().padStart(2, '0')
}
function uuid(i: number): string {
  const h = i.toString(16).padStart(12, '0')
  return `8f14e45f-ceea-467a-9d3c-${h}`
}
function reqId(i: number): string {
  // 16-char base32-ish, varying per occurrence: exactly the value that used to explode grouping.
  return `k3m9p2q7r4s8${pad(i % 100)}zz`
}
