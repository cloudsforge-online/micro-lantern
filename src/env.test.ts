/**
 * Configuration validation. No database — `loadEnv` takes an explicit source object, so every case
 * here is a pure function of its input.
 */

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'

/**
 * GENERATED, NOT WRITTEN, AND THE LITERAL IT REPLACES IS WHY.
 *
 * Every case in this file used to be built on `'a-real-looking-secret-of-sufficient-length'`. It is
 * hyphenated, it is a sentence describing itself, and — read the last two words —
 * `sufficientlength` is one of the placeholder markers `@cloudsforge/secrets` refuses by name. The
 * whole suite was asserting that a value whose own text says it exists to clear a length check is
 * an acceptable credential for the estate's error-tracking plane.
 *
 * Regenerated per run rather than replaced with a better-looking literal, so a placeholder cannot
 * creep back in the next time somebody needs a fixture.
 */
const TOKEN = randomBytes(48).toString('base64')

/** A source that satisfies every required variable, so a case can vary exactly one thing. */
function base(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    LANTERN_DATABASE_URL: 'postgres://lantern:lantern@db:5432/lantern',
    IDENTITY_JWKS_URL: 'http://identity:4001/.well-known/jwks.json',
    IDENTITY_ISSUER: 'http://identity:4001',
    LANTERN_TOKEN: TOKEN,
    ...overrides,
  }
}

// `env.ts` validates `process.env` at IMPORT and exits the process on a bad configuration — right
// for a service, fatal for a test runner. So populate a valid environment first, then import it
// dynamically. `loadEnv` itself is pure over its source, so every case below passes an explicit
// object and never touches `process.env`.
for (const [key, value] of Object.entries(base())) if (value !== undefined) process.env[key] = value
const { EnvError, loadEnv, parseOrigins } = await import('./env.ts')
const { TEST_DSN_VAR } = await import('./testsupport.ts')

describe('the required variables', () => {
  it('loads a complete source', () => {
    const env = loadEnv(base())
    assert.equal(env.databaseUrl, 'postgres://lantern:lantern@db:5432/lantern')
    assert.equal(env.identityIssuer, 'http://identity:4001')
  })

  it('names the missing database variable', () => {
    assert.throws(() => loadEnv(base({ LANTERN_DATABASE_URL: undefined })), (err: unknown) => {
      assert.ok(err instanceof EnvError)
      assert.match(err.message, /LANTERN_DATABASE_URL/)
      return true
    })
  })

  it('names the missing JWKS url', () => {
    assert.throws(() => loadEnv(base({ IDENTITY_JWKS_URL: undefined })), /IDENTITY_JWKS_URL/)
  })

  it('names the missing issuer', () => {
    assert.throws(() => loadEnv(base({ IDENTITY_ISSUER: undefined })), /IDENTITY_ISSUER/)
  })

  it('treats an empty string as missing', () => {
    assert.throws(() => loadEnv(base({ LANTERN_DATABASE_URL: '   ' })), /LANTERN_DATABASE_URL/)
  })
})

describe('the token — the credential whose absence is a supported mode in the frozen service', () => {
  it('is required', () => {
    assert.throws(() => loadEnv(base({ LANTERN_TOKEN: undefined })), /LANTERN_TOKEN is required/)
  })

  it('refuses a known placeholder', () => {
    for (const placeholder of ['changeme', 'CHANGE_ME', 'placeholder', 'secret', 'token']) {
      assert.throws(() => loadEnv(base({ LANTERN_TOKEN: placeholder })), /placeholder/, `for ${placeholder}`)
    }
  })

  /**
   * **THE VALUE THAT IS IN THE COMPOSE FILE TODAY, PINNED AS A FAILURE.**
   *
   * `deploy/compose/docker-compose.estate.yml` carries
   * `LANTERN_TOKEN: estate-only-lantern-token-000000000000` on two lines as a HARDCODED literal,
   * and the same string was measured inside `cloudsforge-estate-lantern-1` on 2026-08-05. It is 38
   * characters, so the 24-character floor this service used to apply could never fail for it —
   * which is micro-org #142, and it is why the floor is gone.
   *
   * Quoted here because it is an already-public defect value with no secrecy left to protect, and
   * because a test that names the exact string the estate shipped is the only kind that cannot be
   * satisfied by a rule that happens to catch something else.
   */
  it('REFUSES THE VALUE THE ESTATE IS RUNNING, which is the whole of this change', () => {
    assert.throws(
      () => loadEnv(base({ LANTERN_TOKEN: 'estate-only-lantern-token-000000000000' })),
      (err: unknown) =>
        err instanceof EnvError &&
        /LANTERN_TOKEN/.test(err.message) &&
        /estateonly/.test(err.message) &&
        // The message names the marker it matched, never the value it matched it in: the fatal
        // handler writes this to stderr and the collector ships it onwards.
        !err.message.includes('estate-only-lantern-token-000000000000'),
    )
  })

  it('refuses a secret shorter than the minimum, and the message says how short', () => {
    // This assertion used to demand the message say "at least 24 characters" — the keystroke floor
    // that let a 38-character placeholder through. Pinning that wording made the test a DEFENCE of
    // the defective rule: any fix that stopped counting to 24 would fail CI, however much better
    // the new rule was. What it asserts now is the property that matters.
    assert.throws(
      () => loadEnv(base({ LANTERN_TOKEN: 'too-short' })),
      (err: unknown) =>
        err instanceof EnvError && /is 9 characters/.test(err.message) && /at least 16/.test(err.message),
    )
  })

  it('refuses a long, well-formed, DEGENERATE value', () => {
    // `'x'.repeat(24)` was asserted here as a VALID token, on the strength of being 24 characters
    // long. It carries zero bits of entropy: every character is the same one. A floor that counts
    // keystrokes cannot tell that apart from a key, which is the second half of why the floor is
    // gone — the first half being the estate placeholder above.
    assert.throws(
      () => loadEnv(base({ LANTERN_TOKEN: 'x'.repeat(24) })),
      (err: unknown) => err instanceof EnvError && /entropy/.test(err.message),
    )
  })

  it('accepts a generated secret', () => {
    const token = randomBytes(48).toString('base64')
    assert.equal(loadEnv(base({ LANTERN_TOKEN: token })).token, token)
  })

  /**
   * An operator's own value is accepted, and that is deliberate.
   *
   * `LANTERN_TOKEN` is a break-glass credential nobody mints — it is typed into a compose file and
   * transcribed out of a runbook during an incident — so it is held to `assertOpaqueSecret` rather
   * than to the estate's base64-or-hex rule. A guard that refused a working hand-set value would be
   * a guard somebody removes, and the marker check that catches the real defect above is identical
   * under both rules.
   */
  it('accepts a hand-set value whose alphabet the estate does not control', () => {
    const typed = 'Zq7!vX#4mT$8kW%2nR&6'
    assert.equal(loadEnv(base({ LANTERN_TOKEN: typed })).token, typed)
  })
})

describe('the docker collector — a container holding /var/run/docker.sock holds root on the host', () => {
  it('is off by default', () => {
    assert.equal(loadEnv(base()).dockerCollector, false)
  })

  it('may be turned on in development', () => {
    const env = loadEnv(base({ NODE_ENV: 'development', LANTERN_DOCKER_COLLECTOR: 'true' }))
    assert.equal(env.dockerCollector, true)
  })

  it('is REFUSED — not warned — outside development', () => {
    assert.throws(
      () => loadEnv(base({ NODE_ENV: 'production', LANTERN_DOCKER_COLLECTOR: 'true' })),
      /development fallback|root on the host/,
    )
  })

  it('is refused in staging too', () => {
    assert.throws(() => loadEnv(base({ NODE_ENV: 'staging', LANTERN_DOCKER_COLLECTOR: '1' })), EnvError)
  })
})

describe('retention ordering — an issue outlives its events', () => {
  it('defaults to 7 days of events and 90 of issues', () => {
    const env = loadEnv(base())
    assert.equal(env.eventRetentionDays, 7)
    assert.equal(env.issueRetentionDays, 90)
  })

  it('refuses issue retention shorter than event retention', () => {
    assert.throws(
      () => loadEnv(base({ LANTERN_EVENT_RETENTION_DAYS: '30', LANTERN_ISSUE_RETENTION_DAYS: '7' })),
      /must be at least/,
    )
  })

  it('accepts equal retentions', () => {
    const env = loadEnv(base({ LANTERN_EVENT_RETENTION_DAYS: '10', LANTERN_ISSUE_RETENTION_DAYS: '10' }))
    assert.equal(env.issueRetentionDays, 10)
  })

  it('rejects a non-integer retention', () => {
    assert.throws(() => loadEnv(base({ LANTERN_EVENT_RETENTION_DAYS: '7.5' })), /whole number/)
  })

  it('rejects a retention out of range', () => {
    assert.throws(() => loadEnv(base({ LANTERN_EVENT_RETENTION_DAYS: '0' })), /between/)
  })
})

describe('the limits', () => {
  it('defaults to four mebibytes of body', () => {
    assert.equal(loadEnv(base()).limits.maxBodyBytes, 4 * 1024 * 1024)
  })

  it('reads overrides', () => {
    const env = loadEnv(base({ LANTERN_MAX_RECORDS: '10', LANTERN_MAX_DEPTH: '4' }))
    assert.equal(env.limits.maxRecords, 10)
    assert.equal(env.limits.maxDepth, 4)
  })

  it('rejects a body limit below the floor', () => {
    assert.throws(() => loadEnv(base({ LANTERN_MAX_BODY_BYTES: '10' })), /between/)
  })
})

describe('the RUM origin allowlist', () => {
  it('is empty by default — the sink is off', () => {
    assert.deepEqual(loadEnv(base()).rumOrigins, [])
  })

  it('parses a comma list into origins', () => {
    assert.deepEqual(parseOrigins('https://a.example, https://b.example'), [
      'https://a.example',
      'https://b.example',
    ])
  })

  it('drops the path, keeping only the origin', () => {
    assert.deepEqual(parseOrigins('https://a.example/dashboard'), ['https://a.example'])
  })

  it('refuses a wildcard', () => {
    assert.throws(() => parseOrigins('*'), /may not be/)
  })

  it('refuses a non-absolute entry', () => {
    assert.throws(() => parseOrigins('a.example'), /absolute origin/)
  })

  it('refuses a non-http scheme', () => {
    assert.throws(() => parseOrigins('ftp://a.example'), /http or https/)
  })

  it('refuses a duplicate origin', () => {
    assert.throws(() => parseOrigins('https://a.example, https://a.example/x'), /twice/)
  })
})

describe('log level', () => {
  it('defaults to info', () => {
    assert.equal(loadEnv(base()).logLevel, 'info')
  })

  it('accepts a known level', () => {
    assert.equal(loadEnv(base({ LOG_LEVEL: 'debug' })).logLevel, 'debug')
  })

  it('refuses an unknown level', () => {
    assert.throws(() => loadEnv(base({ LOG_LEVEL: 'verbose' })), /LOG_LEVEL must be one of/)
  })
})

describe('the test-database variable is spelled the way CI exports it', () => {
  it('is LANTERN_TEST_DATABASE_URL', () => {
    // A different spelling silently skips the DB suite, and the reusable workflow FAILS the build
    // on a skipped DB suite. This is the one string that keeps the two in agreement.
    assert.equal(TEST_DSN_VAR, 'LANTERN_TEST_DATABASE_URL')
  })
})
