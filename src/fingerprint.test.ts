/**
 * Grouping. The product, and the file whose whole job is to NOT produce one group per occurrence.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  FRAMEWORK_LINES,
  NORMAL_RULES,
  fingerprint,
  isFault,
  issueTitle,
  normalise,
  topFrame,
  type Groupable,
} from './fingerprint.ts'

function fault(overrides: Partial<Groupable> = {}): Groupable {
  return {
    service: 'ledger',
    severity: 'error',
    msg: 'something broke',
    source: 'otlp',
    statusCode: null,
    errType: null,
    errMessage: null,
    errStack: null,
    ...overrides,
  }
}

describe('normalise strips the parts that vary per occurrence', () => {
  const table: Array<{ name: string; input: string; expect: string }> = [
    { name: 'a uuid', input: 'user 8f14e45f-ceea-467a-9d3c-6f5a2b1c0d3e not found', expect: 'user <uuid> not found' },
    { name: 'an iso timestamp', input: 'at 2026-07-31T14:50:03.848Z it failed', expect: 'at <time> it failed' },
    { name: 'a memory address', input: 'segfault at 0x7ffee3b2c1d0 now', expect: 'segfault at <addr> now' },
    { name: 'a long hash', input: 'sha deadbeefcafebabe1234 mismatch', expect: 'sha <hash> mismatch' },
    { name: 'a twelve-char short id', input: 'container 3f2a1b0c9d8e died', expect: 'container <hash> died' },
    { name: 'an email', input: 'invite jane.doe@example.com bounced', expect: 'invite <email> bounced' },
    { name: 'an ipv4', input: 'refused 10.0.0.5:4001 conn', expect: 'refused <ip> conn' },
    { name: 'a url', input: 'GET https://api.example.com/v1/x failed', expect: 'GET <url> failed' },
    { name: 'a number with unit', input: 'took 1234ms to answer', expect: 'took <n> to answer' },
    { name: 'a source position', input: 'at server.ts:412:19 threw', expect: 'at server.ts:<pos> threw' },
    { name: 'a double-quoted value', input: 'relation "orders" does not exist', expect: 'relation "<str>" does not exist' },
  ]

  for (const row of table) {
    it(`collapses ${row.name}`, () => {
      assert.equal(normalise(row.input), row.expect)
    })
  }

  it('collapses a base32 request id — the defect one library away from the log line', () => {
    // The runtime's newRequestId emits 16 chars of Crockford base32; the frozen \b[0-9a-f]{16,}\b
    // rule never matched it, so a message quoting its own request id grouped per request.
    assert.equal(normalise('request k3m9p2q7r4s8t1v6 failed'), 'request <id> failed')
  })
})

describe('the failure mode this file exists to prevent: one group per occurrence', () => {
  it('groups a noisy message stably across occurrences that differ only in the noise', () => {
    const a = fault({
      msg: 'failed to load user 8f14e45f-ceea-467a-9d3c-6f5a2b1c0d3e at 2026-07-31T14:50:03.848Z addr 0x7ffee3b2c1d0 req k3m9p2q7r4s8t1v6',
    })
    const b = fault({
      msg: 'failed to load user 11111111-2222-4333-8444-555566667777 at 2026-07-30T09:12:00.000Z addr 0x00007ff0aabb req z9y8x7w6v5u4t3s2',
    })
    const c = fault({
      msg: 'failed to load user 99999999-8888-4777-8666-555544443333 at 2025-01-01T00:00:00.000Z addr 0xdeadbeef00 req h5j9k2m6n4p8q1r7',
    })
    assert.equal(fingerprint(a), fingerprint(b))
    assert.equal(fingerprint(b), fingerprint(c))
    assert.ok(fingerprint(a) !== null)
  })

  it('a container id and a git sha do not each spawn a group', () => {
    const a = fault({ msg: 'container 3f2a1b0c9d8e exited nonzero building a1b2c3d4e5f6' })
    const b = fault({ msg: 'container 9e8d7c6b5a40 exited nonzero building f6e5d4c3b2a1' })
    assert.equal(fingerprint(a), fingerprint(b))
  })

  it('keeps genuinely different faults apart', () => {
    const refused = fault({ errType: 'ECONNREFUSED', msg: 'connect failed' })
    const timedOut = fault({ errType: 'ETIMEDOUT', msg: 'connect failed' })
    assert.ok(fingerprint(refused) !== fingerprint(timedOut))
  })

  it('two services failing the same way are two problems', () => {
    assert.ok(fingerprint(fault({ service: 'ledger' })) !== fingerprint(fault({ service: 'market' })))
  })

  it('two call sites raising the same text are two bugs', () => {
    const here = fault({ errMessage: 'boom', errStack: 'Error: boom\n    at src/a.ts:1:1' })
    const there = fault({ errMessage: 'boom', errStack: 'Error: boom\n    at src/b.ts:1:1' })
    assert.ok(fingerprint(here) !== fingerprint(there))
  })
})

describe('what is not grouped', () => {
  it('returns null for a non-fault', () => {
    assert.equal(fingerprint(fault({ severity: 'info', statusCode: 200 })), null)
  })

  it('groups a 5xx even when logged below error', () => {
    assert.ok(fingerprint(fault({ severity: 'info', statusCode: 503 })) !== null)
  })

  it('does not group a 4xx', () => {
    assert.equal(fingerprint(fault({ severity: 'info', statusCode: 404 })), null)
  })

  it('skips a bare framework line with no error attached', () => {
    for (const line of FRAMEWORK_LINES) {
      assert.equal(fingerprint(fault({ msg: line })), null, `for "${line}"`)
    }
  })

  it('still groups a framework line that carries a real error', () => {
    assert.ok(fingerprint(fault({ msg: 'request completed', errMessage: 'pool exhausted' })) !== null)
  })
})

describe('isFault', () => {
  it('is true for error and fatal', () => {
    assert.ok(isFault(fault({ severity: 'error' })))
    assert.ok(isFault(fault({ severity: 'fatal' })))
  })

  it('is true for a 5xx at any severity', () => {
    assert.ok(isFault(fault({ severity: 'info', statusCode: 500 })))
  })

  it('is false for warn and below without a 5xx', () => {
    assert.ok(!isFault(fault({ severity: 'warn' })))
    assert.ok(!isFault(fault({ severity: 'info', statusCode: 200 })))
  })
})

describe('topFrame — where the fault is, not where it surfaced', () => {
  it('skips node_modules and node internals for the first frame that is ours', () => {
    const stack = [
      'Error: boom',
      '    at Object.<anonymous> (node:internal/process/task_queues:95:5)',
      '    at run (/app/node_modules/pg/lib/client.js:20:10)',
      '    at handler (/app/src/ledger.ts:88:12)',
    ].join('\n')
    assert.equal(topFrame(stack), 'src/ledger.ts:88')
  })

  it('normalises an absolute path to the repo root', () => {
    const stack = 'Error\n    at x (/home/ci/checkout/services/pay/src/post.ts:12:3)'
    assert.equal(topFrame(stack), 'src/post.ts:12')
  })

  it('is empty for an absent stack', () => {
    assert.equal(topFrame(undefined), '')
    assert.equal(topFrame(null), '')
    assert.equal(topFrame(''), '')
  })
})

describe('issueTitle', () => {
  it('prefers the human message and appends the error text', () => {
    const title = issueTitle(fault({ msg: 'cannot verify tokens', errMessage: 'ENOTFOUND identity' }))
    assert.equal(title, 'cannot verify tokens — ENOTFOUND identity')
  })

  it('does not duplicate when the message already contains the error', () => {
    assert.equal(issueTitle(fault({ msg: 'boom happened: detail', errMessage: 'detail' })), 'boom happened: detail')
  })

  it('falls back to the error type and message', () => {
    const title = issueTitle(fault({ msg: '(no message)', errType: 'RangeError', errMessage: 'out of range' }))
    assert.equal(title, 'RangeError: out of range')
  })

  it('caps at 300 characters', () => {
    assert.ok(issueTitle(fault({ msg: 'x'.repeat(500) })).length <= 300)
  })
})

describe('the rules are ordered and the order is asserted', () => {
  it('places uuid before hash before the id rules before number', () => {
    const order = NORMAL_RULES.map((rule) => rule.name)
    assert.ok(order.indexOf('uuid') < order.indexOf('hash'))
    assert.ok(order.indexOf('time') < order.indexOf('number'))
    assert.ok(order.indexOf('ip') < order.indexOf('url'))
    assert.ok(order.indexOf('pos') < order.indexOf('number'))
  })

  it('is idempotent — normalising a normalised string changes nothing', () => {
    const once = normalise('user 8f14e45f-ceea-467a-9d3c-6f5a2b1c0d3e at 2026-07-31T00:00:00Z')
    assert.equal(normalise(once), once)
  })
})
