/**
 * The browser sink: the field mapping, the clamps, the drop of user_id, and the per-client quota
 * at the unit level — and then `insertRum` against a real Postgres, reading the stored column back.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * WHY THE LAST BLOCK IN THIS FILE TALKS TO A DATABASE.
 *
 * `insertRum` stored `attributes` DOUBLE-ENCODED for its whole life — `JSON.stringify` here plus
 * postgres.js's own JSON serialisation there — so the jsonb column held a JSON *string*.
 * `jsonb_typeof(attributes)` returned 'string' and `attributes->>'type'` returned null: every
 * attribute a browser sent was stored, and none of it was readable.
 *
 * Nothing caught it, and that is the part worth fixing. The tests above assert on the in-memory
 * object BEFORE it reaches the database, `reads.ts` did not select the column at all, and
 * `server.test.ts` asserted on `attributes::text`, which contains the same substrings under either
 * encoding. There was no path in the suite through which a malformed write could be OBSERVED.
 *
 * So `attributesRoundTrip` below reads the column back out of Postgres and asserts on
 * `jsonb_typeof` and on key extraction. Restore the `JSON.stringify` in `rum.ts` and it goes red.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { RUM_KINDS, RumQuota, fromWire, insertRum, type RumSample } from './rum.ts'
import type { Limits } from './env.ts'
import type { SecretKind } from './scrub.ts'
import { db, migrateTestDb, openDb, resetLantern, skip } from './testsupport.ts'

const LIMITS: Limits = {
  maxBodyBytes: 1024 * 1024,
  maxRecords: 1000,
  maxAttributes: 64,
  maxDepth: 6,
  maxStringBytes: 8_192,
}

function map(raw: unknown): { sample: ReturnType<typeof fromWire>; removed: Map<SecretKind, number> } {
  const removed = new Map<SecretKind, number>()
  return { sample: fromWire(raw, LIMITS, removed), removed }
}

describe('fromWire keeps a well-formed sample', () => {
  it('maps the fields', () => {
    const { sample } = map({
      app: 'hub-web',
      kind: 'page_load',
      route: '/dashboard',
      valueMs: 1234,
      statusCode: 200,
      traceId: '00112233445566778899aabbccddeeff',
      session: 'tab-42',
    })
    assert.ok(sample)
    assert.equal(sample!.app, 'hub-web')
    assert.equal(sample!.kind, 'page_load')
    assert.equal(sample!.valueMs, 1234)
    assert.equal(sample!.traceId, '00112233445566778899aabbccddeeff')
  })

  it('accepts every known kind', () => {
    for (const kind of RUM_KINDS) {
      assert.ok(map({ app: 'x', kind }).sample, `kind ${kind}`)
    }
  })
})

describe('fromWire drops what it must not keep', () => {
  it('drops an unknown kind entirely', () => {
    assert.equal(map({ app: 'x', kind: 'made_up' }).sample, null)
  })

  it('drops a sample with no app', () => {
    assert.equal(map({ kind: 'error' }).sample, null)
  })

  it('NEVER carries a user_id — the field is simply not read', () => {
    const { sample } = map({ app: 'x', kind: 'error', userId: 'user-123', user: 'alice', email: 'a@b.com' })
    assert.ok(sample)
    const serialised = JSON.stringify(sample)
    assert.doesNotMatch(serialised, /user-123/)
    assert.doesNotMatch(serialised, /alice/)
    // Even the promoted columns carry no identity: userId is not a field on RumSample at all.
    assert.ok(!('userId' in (sample as object)))
  })

  it('scrubs credentials planted in the attribute bag', () => {
    const { sample, removed } = map({
      app: 'x',
      kind: 'fetch_error',
      // A secret under a sensitive KEY is dropped wholesale; a secret inside a string VALUE is
      // scrubbed by shape. Both paths are exercised here.
      attributes: { authorization: 'Bearer abcdef0123456789ABCDEF', detail: 'failed key=sk_live_abcdefgh12345678' },
    })
    assert.ok(sample)
    const serialised = JSON.stringify(sample!.attributes)
    assert.doesNotMatch(serialised, /abcdef0123456789ABCDEF/)
    assert.doesNotMatch(serialised, /sk_live_abcdefgh12345678/)
    assert.ok((removed.get('sensitive-key') ?? 0) >= 1)
    assert.ok((removed.get('api-key') ?? 0) >= 1)
  })
})

describe('fromWire clamps the numbers to their column CHECKs', () => {
  it('drops a negative duration — a clock that moved backwards', () => {
    assert.equal(map({ app: 'x', kind: 'page_load', valueMs: -5 }).sample!.valueMs, null)
  })

  it('drops a duration over ten minutes — the browser was closed, not slow', () => {
    assert.equal(map({ app: 'x', kind: 'page_load', valueMs: 600_001 }).sample!.valueMs, null)
  })

  it('drops a status code of a thousand or more', () => {
    assert.equal(map({ app: 'x', kind: 'fetch_error', statusCode: 1000 }).sample!.statusCode, null)
  })

  it('drops a malformed trace id', () => {
    assert.equal(map({ app: 'x', kind: 'error', traceId: 'nothex' }).sample!.traceId, null)
    assert.equal(map({ app: 'x', kind: 'error', traceId: '0'.repeat(32) }).sample!.traceId, null)
  })
})

describe('RumQuota — a per-client fixed window', () => {
  it('allows up to the limit and then refuses within a window', () => {
    let now = 0
    const quota = new RumQuota(3, () => now)
    assert.ok(quota.allow('1.2.3.4'))
    assert.ok(quota.allow('1.2.3.4'))
    assert.ok(quota.allow('1.2.3.4'))
    assert.ok(!quota.allow('1.2.3.4'))
  })

  it('resets on the next minute', () => {
    let now = 0
    const quota = new RumQuota(1, () => now)
    assert.ok(quota.allow('c'))
    assert.ok(!quota.allow('c'))
    now = 60_000
    assert.ok(quota.allow('c'))
  })

  it('counts each client independently', () => {
    const quota = new RumQuota(1, () => 0)
    assert.ok(quota.allow('a'))
    assert.ok(quota.allow('b'))
    assert.ok(!quota.allow('a'))
  })
})

/* ------------------------------------------------------- the stored column, not the held object */

describe('insertRum stores attributes as jsonb the database can read', { skip }, () => {
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

  function sample(attributes: Record<string, unknown>): RumSample {
    return {
      app: 'hub-web',
      kind: 'error',
      route: '/dashboard',
      valueMs: null,
      statusCode: null,
      requestId: null,
      traceId: null,
      session: null,
      attributes,
    }
  }

  /** The read-back, done in SQL so the assertion is about the COLUMN and not about a JS value. */
  async function attributesRoundTrip(): Promise<{
    typeof_: string
    type: string | null
    message: string | null
    nested: string | null
    keys: string[]
  }> {
    const rows = (await sql.unsafe(`
      select jsonb_typeof(attributes)          as typeof_,
             attributes->>'type'               as type,
             attributes->>'message'            as message,
             attributes#>>'{context,source}'   as nested,
             coalesce(
               (select array_agg(k order by k) from jsonb_object_keys(attributes) k),
               array[]::text[]
             )                                 as keys
        from rum_samples
    `)) as unknown as Array<{ typeof_: string; type: string | null; message: string | null; nested: string | null; keys: string[] }>
    assert.equal(rows.length, 1, 'exactly one row was inserted')
    return rows[0]!
  }

  /**
   * The assertion the old suite could not make.
   *
   * `jsonb_typeof` is the whole point: under the double-encode it answers 'string', and every one
   * of the extractions below answers null while `attributes::text` — what the previous test read —
   * still contains all the same substrings and passes.
   */
  it('stores an OBJECT, so jsonb_typeof is object and not string', async () => {
    await insertRum(db(sql), [sample({ type: 'TypeError', message: 'x is not a function' })])
    assert.equal((await attributesRoundTrip()).typeof_, 'object')
  })

  it('lets the database extract a key — the browser error message is readable in SQL', async () => {
    await insertRum(db(sql), [
      sample({
        type: 'TypeError',
        message: 'x is not a function',
        context: { source: 'https://hub.example/assets/index-abc.js' },
      }),
    ])
    const row = await attributesRoundTrip()
    assert.equal(row.type, 'TypeError')
    assert.equal(row.message, 'x is not a function')
    // Nested, because a double-encode is not the only way to lose depth and `context` is where
    // `obs.ts` puts the stack frame an operator actually opens.
    assert.equal(row.nested, 'https://hub.example/assets/index-abc.js')
    assert.deepEqual(row.keys, ['context', 'message', 'type'])
  })

  /**
   * `jsonb_object_keys` on a JSON string RAISES rather than returning nothing, so this case fails
   * loudly under the defect instead of quietly comparing two empty lists.
   */
  it('is an object a jsonb operator can walk, for every kind the sink accepts', async () => {
    for (const kind of RUM_KINDS) {
      await resetLantern(sql)
      await insertRum(db(sql), [{ ...sample({ type: 'Probe', message: kind }), kind }])
      const row = await attributesRoundTrip()
      assert.equal(row.typeof_, 'object', `kind ${kind}`)
      assert.equal(row.message, kind, `kind ${kind}`)
    }
  })

  it('stores an empty bag as an empty OBJECT, not as the string "{}"', async () => {
    await insertRum(db(sql), [sample({})])
    const row = await attributesRoundTrip()
    assert.equal(row.typeof_, 'object')
    assert.deepEqual(row.keys, [])
  })

  /**
   * The scrubber's output must survive the write too. `rum.test.ts` already proves the credential
   * is gone from the in-memory bag; this proves the bag that reaches the column is the scrubbed
   * one AND that it is still queryable — a redaction that arrives as an opaque string is a
   * redaction nobody can audit.
   */
  it('carries the SCRUBBED bag into a column that can still be queried by key', async () => {
    const removed = new Map<SecretKind, number>()
    const mapped = fromWire(
      {
        app: 'hub-web',
        kind: 'fetch_error',
        attributes: { authorization: 'Bearer abcdef0123456789ABCDEF', detail: 'boom', type: 'NetworkError' },
      },
      LIMITS,
      removed,
    )
    assert.ok(mapped)
    await insertRum(db(sql), [mapped!])
    const row = await attributesRoundTrip()
    assert.equal(row.typeof_, 'object')
    assert.equal(row.type, 'NetworkError')
    const raw = (await sql.unsafe(`select attributes::text as t from rum_samples`)) as unknown as Array<{ t: string }>
    assert.doesNotMatch(raw[0]!.t, /abcdef0123456789ABCDEF/)
  })
})
