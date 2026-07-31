/**
 * Configuration validation. No database — `loadEnv` takes an explicit source object, so every case
 * here is a pure function of its input.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

/** A source that satisfies every required variable, so a case can vary exactly one thing. */
function base(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    LANTERN_DATABASE_URL: 'postgres://lantern:lantern@db:5432/lantern',
    IDENTITY_JWKS_URL: 'http://identity:4001/.well-known/jwks.json',
    IDENTITY_ISSUER: 'http://identity:4001',
    LANTERN_TOKEN: 'a-real-looking-secret-of-sufficient-length',
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

  it('refuses a secret shorter than the minimum', () => {
    assert.throws(() => loadEnv(base({ LANTERN_TOKEN: 'too-short' })), /at least 24 characters/)
  })

  it('accepts a real-looking secret', () => {
    const env = loadEnv(base({ LANTERN_TOKEN: 'x'.repeat(24) }))
    assert.equal(env.token.length, 24)
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
