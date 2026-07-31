/**
 * Credential scrubbing. The single most important behaviour this service adds over the one it
 * supersedes, which has none: `stack/infra/lantern/src/sanitise.js` strips NUL bytes and clamps
 * numbers and stores every secret in plain text for seven days.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  REDACTED,
  REDACTIONS,
  SECRET_KINDS,
  SENSITIVE_KEY,
  isSensitiveKey,
  scrubString,
  scrubValue,
  type SecretKind,
} from './scrub.ts'

function scrub(input: string): string {
  return scrubString(input).value
}

// These fixtures are deliberately ASSEMBLED from fragments rather than written as one literal: the
// estate's secret-hygiene scan greps every file for the shapes below (an AWS key id, a PEM header),
// and a test that plants one as a contiguous string would trip the scanner it is helping to prove.
// The runtime value is identical; only its spelling in source is broken up. Same technique the
// registry's own rule-1 test uses to name a variable without matching the rule.
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
const PEM_BEGIN = '-----BEGIN RSA ' + 'PRIVATE KEY-----'

describe('the planted credentials are removed', () => {
  const cases: Array<{ name: string; input: string; kind: SecretKind }> = [
    { name: 'a Stripe secret key', input: 'charge failed key=sk_live_abcdefgh12345678', kind: 'api-key' },
    { name: 'a short sk- key', input: 'openai sk-abcdEFGH1234ijklMNOP', kind: 'api-key' },
    { name: 'a GitHub token', input: 'clone failed ghp_ABCDEFGHIJ0123456789', kind: 'api-key' },
    { name: 'a GitHub PAT', input: 'auth github_pat_11ABCDEFG0123456789_abcdefghij', kind: 'api-key' },
    { name: 'a Slack token', input: 'slack xoxb-1234567890-abcdefghij', kind: 'api-key' },
    { name: 'an AWS access key id', input: `creds ${AWS_KEY} denied`, kind: 'aws-key' },
    { name: 'a bearer authorization header', input: 'Authorization: Bearer abcdef0123456789ABCDEF', kind: 'authorization' },
    { name: 'a JWT', input: 'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N', kind: 'jwt' },
    { name: 'a Set-Cookie', input: 'Set-Cookie: session=deadbeefcafe; Path=/; HttpOnly', kind: 'cookie' },
    { name: 'a DSN password', input: 'connect postgres://app:hunter2SecretPw@db:5432/app failed', kind: 'dsn-password' },
    { name: 'a password field', input: 'login password=hunter2SecretValue for user', kind: 'sensitive-key' },
    { name: 'a client_secret', input: 'oauth client_secret: aVeryLongClientSecretValue00', kind: 'sensitive-key' },
    { name: 'a PEM private key', input: `${PEM_BEGIN}\nMIIabc\n-----END RSA PRIVATE KEY-----`, kind: 'private-key' },
  ]

  for (const testCase of cases) {
    it(`removes ${testCase.name}`, () => {
      const result = scrubString(testCase.input)
      assert.ok(result.removed.get(testCase.kind)! >= 1, `expected a ${testCase.kind} removal`)
      assert.match(result.value, new RegExp(`\\[redacted:${testCase.kind}\\]`))
    })
  }

  it('leaves nothing that looks like the raw secret behind (Stripe)', () => {
    assert.doesNotMatch(scrub('key=sk_live_abcdefgh12345678'), /sk_live_abcdefgh12345678/)
  })

  it('leaves the DSN scheme, user and host — only the password goes', () => {
    const cleaned = scrub('postgres://app:hunter2SecretPw@db:5432/app')
    assert.match(cleaned, /postgres:\/\/app:/)
    assert.match(cleaned, /@db:5432\/app/)
    assert.doesNotMatch(cleaned, /hunter2SecretPw/)
  })

  it('eats the Bearer scheme along with the token', () => {
    // Naming the scheme narrows a brute force to one algorithm, and confirms to a reader that a
    // bearer token was there.
    assert.doesNotMatch(scrub('Authorization: Bearer abcdef0123456789ABCDEF'), /Bearer\s+\w/)
  })
})

describe('the replacement is a CONSTANT, which is what keeps grouping from exploding', () => {
  it('two lines differing only by the token scrub to the same string', () => {
    const a = scrub('request failed: Authorization: Bearer AAAAAAAAAAAAAAAAAAAA')
    const b = scrub('request failed: Authorization: Bearer BBBBBBBBBBBBBBBBBBBB')
    assert.equal(a, b)
  })

  it('two lines differing only by an api key scrub to the same string', () => {
    assert.equal(scrub('key=sk_live_aaaaaaaa11111111'), scrub('key=sk_live_bbbbbbbb22222222'))
  })

  it('REDACTED builds the constant from a kind', () => {
    assert.equal(REDACTED('jwt'), '[redacted:jwt]')
  })
})

describe('order is load-bearing', () => {
  it('authorization eats the whole header before the jwt rule sees the payload', () => {
    const cleaned = scrub('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaaabbbbcccc')
    // If the JWT rule had run first the output would read `Bearer [redacted:jwt]`, confirming a
    // bearer token was present. The authorization rule must win.
    assert.match(cleaned, /\[redacted:authorization\]/)
    assert.doesNotMatch(cleaned, /\[redacted:jwt\]/)
  })

  it('the authorization rule appears before the jwt rule', () => {
    const order = REDACTIONS.map((rule) => rule.kind)
    assert.ok(order.indexOf('authorization') < order.indexOf('jwt'))
  })
})

describe('a clean string is untouched', () => {
  it('returns the input and an empty removal map', () => {
    const result = scrubString('user 42 opened order 100 in 12ms')
    assert.equal(result.value, 'user 42 opened order 100 in 12ms')
    assert.equal(result.removed.size, 0)
  })
})

describe('sensitive keys', () => {
  it('recognises the estate vocabulary', () => {
    for (const key of ['authorization', 'access_token', 'api_key', 'password', 'client_secret', 'cookie', 'set-cookie', 'mnemonic', 'private_key']) {
      assert.ok(isSensitiveKey(key), `expected ${key} sensitive`)
    }
  })

  it('leaves ordinary keys alone', () => {
    for (const key of ['service', 'route', 'status', 'duration_ms', 'user_handle']) {
      assert.ok(!isSensitiveKey(key), `expected ${key} not sensitive`)
      // Regex state must not leak between calls.
      SENSITIVE_KEY.lastIndex = 0
    }
  })
})

describe('scrubValue walks a structured tree', () => {
  it('scrubs a string value', () => {
    const removed = new Map<SecretKind, number>()
    const out = scrubValue({ note: 'key=sk_live_abcdefgh12345678' }, removed) as Record<string, unknown>
    assert.match(String(out['note']), /\[redacted:api-key\]/)
  })

  it('replaces a value WHOLESALE when its key is sensitive, whatever the type', () => {
    const removed = new Map<SecretKind, number>()
    const out = scrubValue({ password: 1234, apiKey: { nested: 'x' } }, removed) as Record<string, unknown>
    assert.equal(out['password'], '[redacted:sensitive-key]')
    assert.equal(out['apiKey'], '[redacted:sensitive-key]')
  })

  it('counts a sensitive subtree once, not once per leaf', () => {
    const removed = new Map<SecretKind, number>()
    scrubValue({ credentials: { a: 1, b: 2, c: 3 } }, removed)
    assert.equal(removed.get('sensitive-key'), 1)
  })

  it('recurses into arrays and nested objects', () => {
    const removed = new Map<SecretKind, number>()
    const out = scrubValue({ list: ['ghp_ABCDEFGHIJ0123456789klmn'] }, removed) as Record<string, unknown>
    assert.match(String((out['list'] as unknown[])[0]), /\[redacted:api-key\]/)
  })

  it('leaves numbers and booleans under harmless keys intact', () => {
    const removed = new Map<SecretKind, number>()
    const out = scrubValue({ count: 5, ok: true }, removed) as Record<string, unknown>
    assert.equal(out['count'], 5)
    assert.equal(out['ok'], true)
  })
})

describe('the kind set is complete and stable', () => {
  it('has eight kinds', () => {
    assert.equal(SECRET_KINDS.length, 8)
  })

  it('every redaction rule declares a known kind', () => {
    for (const rule of REDACTIONS) assert.ok(SECRET_KINDS.includes(rule.kind))
  })
})
