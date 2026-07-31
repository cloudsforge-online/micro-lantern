/**
 * The browser sink, at the unit level: the field mapping, the clamps, the drop of user_id, and the
 * per-client quota. The database round trip is covered in `server.test.ts`.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { RUM_KINDS, RumQuota, fromWire } from './rum.ts'
import type { Limits } from './env.ts'
import type { SecretKind } from './scrub.ts'

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
