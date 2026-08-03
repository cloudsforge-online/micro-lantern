/**
 * The HTTP surface, driven over a real socket against a real Postgres.
 *
 * The verifier is a fake — a plain object implementing `principal` — so no JWT machinery is needed
 * to prove the static-token door, the 401 path, and that `/metrics` costs a credential.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type postgres from 'postgres'
import { TokenError, type Principal } from '@cloudsforge/auth'
import { Lifecycle, postgresProbe } from '@cloudsforge/lifecycle'
import { createServer, type PrincipalVerifier, type ServerDeps } from './server.ts'
import { RumQuota } from './rum.ts'
import type { Limits } from './env.ts'
import { db, migrateTestDb, openDb, quietLogger, resetLantern, skip, testMetrics } from './testsupport.ts'

const LIMITS: Limits = {
  maxBodyBytes: 4 * 1024 * 1024,
  maxRecords: 5_000,
  maxAttributes: 128,
  maxDepth: 8,
  maxStringBytes: 8_192,
}

const TOKEN = 'a-real-looking-static-token-000000000'

/** A verifier that accepts exactly one bearer token, as a user. Everything else is a 401. */
const verifier: PrincipalVerifier = {
  async principal(token: string): Promise<Principal> {
    if (token === 'good-user') return { kind: 'user', userId: 'u1', handle: 'op', roles: [] }
    throw new TokenError('bad token', 'invalid')
  },
}

interface Running {
  readonly server: Server
  readonly url: string
  close(): Promise<void>
}

async function start(sql: postgres.Sql, overrides: Partial<ServerDeps> = {}): Promise<Running> {
  const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100 })
  lifecycle.addProbe(postgresProbe('postgres', () => sql`select 1`))
  const deps: ServerDeps = {
    lifecycle,
    logger: quietLogger(),
    metrics: testMetrics(),
    verifier,
    sql: db(sql),
    token: TOKEN,
    limits: LIMITS,
    rumOrigins: ['http://app.example'],
    rumQuota: new RumQuota(1000),
    traceUrlTemplate: 'https://tempo.example/trace/{traceId}',
    ...overrides,
  }
  const server = createServer(deps)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  lifecycle.markReady()
  const port = (server.address() as AddressInfo).port
  return {
    server,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

describe('the HTTP surface', { skip }, () => {
  let sql: postgres.Sql
  let app: Running

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
    app = await start(sql)
  })
  beforeEach(async () => {
    await resetLantern(sql)
  })
  after(async () => {
    await app.close()
    await sql.end({ timeout: 5 })
  })

  /* ---------------------------------------------------------------- health */

  describe('the three health endpoints exist', () => {
    it('/livez is static and answers 200', async () => {
      const res = await fetch(`${app.url}/livez`)
      assert.equal(res.status, 200)
    })

    it('/readyz probes Postgres and answers 200 when ready', async () => {
      const res = await fetch(`${app.url}/readyz`)
      assert.equal(res.status, 200)
      const body = (await res.json()) as { ready: boolean }
      assert.equal(body.ready, true)
    })
  })

  /* ---------------------------------------------------------------- /metrics is gated */

  describe('/metrics requires a credential', () => {
    it('answers 401 without one', async () => {
      const res = await fetch(`${app.url}/metrics`)
      assert.equal(res.status, 401)
    })

    it('answers 200 to the static token', async () => {
      const res = await fetch(`${app.url}/metrics`, { headers: { 'x-lantern-token': TOKEN } })
      assert.equal(res.status, 200)
      assert.match(await res.text(), /lantern_up/)
    })

    it('answers 200 to a valid identity token', async () => {
      const res = await fetch(`${app.url}/metrics`, { headers: { authorization: 'Bearer good-user' } })
      assert.equal(res.status, 200)
    })

    it('answers 401 to a wrong static token', async () => {
      const res = await fetch(`${app.url}/metrics`, { headers: { 'x-lantern-token': 'wrong' } })
      assert.equal(res.status, 401)
    })
  })

  /* ---------------------------------------------------------------- OTLP ingest */

  describe('POST /otlp/v1/logs', () => {
    it('stores a JSON export and scrubs a credential before persistence', async () => {
      const payload = {
        resourceLogs: [
          {
            resource: { attributes: [{ key: 'service.name', value: { stringValue: 'ledger' } }] },
            scopeLogs: [
              {
                logRecords: [
                  {
                    severityNumber: 17,
                    body: { stringValue: 'charge failed key=sk_live_abcdefgh12345678xyz' },
                    traceId: '00112233445566778899aabbccddeeff',
                    attributes: [{ key: 'request.id', value: { stringValue: 'k3m9p2q7r4s8t1v6' } }],
                  },
                ],
              },
            ],
          },
        ],
      }
      const res = await fetch(`${app.url}/otlp/v1/logs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
      assert.equal(res.status, 200)

      const rows = (await sql`select msg, service, trace_id from events`) as unknown as Array<{ msg: string; service: string; trace_id: string }>
      assert.equal(rows.length, 1)
      assert.equal(rows[0]!.service, 'ledger')
      assert.doesNotMatch(rows[0]!.msg, /sk_live_abcdefgh12345678xyz/)
      assert.match(rows[0]!.msg, /\[redacted:api-key\]/)
    })

    it('refuses an oversized body with 413 and stores nothing', async () => {
      const small = await start(sql, { limits: { ...LIMITS, maxBodyBytes: 64 } })
      try {
        const res = await fetch(`${small.url}/otlp/v1/logs`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ resourceLogs: [{ scopeLogs: [{ logRecords: [{ body: { stringValue: 'x'.repeat(500) } }] }] }] }),
        })
        assert.equal(res.status, 413)
        const rows = (await sql`select count(*)::int as n from events`) as unknown as Array<{ n: number }>
        assert.equal(rows[0]!.n, 0)
      } finally {
        await small.close()
      }
    })

    it('answers 415 to an unsupported content type', async () => {
      const res = await fetch(`${app.url}/otlp/v1/logs`, {
        method: 'POST',
        headers: { 'content-type': 'text/xml' },
        body: '<nope/>',
      })
      assert.equal(res.status, 415)
    })

    it('is reachable without any credential — the collector presents none', async () => {
      const res = await fetch(`${app.url}/otlp/v1/logs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ resourceLogs: [] }),
      })
      assert.equal(res.status, 200)
    })
  })

  /* ---------------------------------------------------------------- browser sink */

  describe('POST /ingest/client', () => {
    it('accepts a sample from an allowed origin and drops user_id', async () => {
      const res = await fetch(`${app.url}/ingest/client`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://app.example' },
        body: JSON.stringify({ samples: [{ app: 'hub-web', kind: 'page_load', valueMs: 900, userId: 'user-77' }] }),
      })
      assert.equal(res.status, 202)
      const rows = (await sql`select app, attributes::text as attrs from rum_samples`) as unknown as Array<{ app: string; attrs: string }>
      assert.equal(rows.length, 1)
      assert.equal(rows[0]!.app, 'hub-web')
      assert.doesNotMatch(rows[0]!.attrs, /user-77/)
    })

    it('refuses an origin that is not on the allowlist', async () => {
      const res = await fetch(`${app.url}/ingest/client`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
        body: JSON.stringify({ samples: [{ app: 'x', kind: 'error' }] }),
      })
      assert.equal(res.status, 400)
    })

    it('enforces the per-client quota', async () => {
      const one = await start(sql, { rumQuota: new RumQuota(1) })
      try {
        const post = () =>
          fetch(`${one.url}/ingest/client`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', origin: 'http://app.example' },
            body: JSON.stringify({ samples: [{ app: 'x', kind: 'error' }] }),
          })
        assert.equal((await post()).status, 202)
        assert.equal((await post()).status, 429)
      } finally {
        await one.close()
      }
    })

    it('is disabled when no origins are configured', async () => {
      const off = await start(sql, { rumOrigins: [] })
      try {
        const res = await fetch(`${off.url}/ingest/client`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://app.example' },
          body: JSON.stringify({ samples: [{ app: 'x', kind: 'error' }] }),
        })
        assert.equal(res.status, 404)
      } finally {
        await off.close()
      }
    })

    /**
     * A batch that stores nothing must SAY it stored nothing and why. The prior behaviour —
     * `202 {"stored":0}` for a wholly discarded batch — is what let sixteen frontends believe they
     * were reporting telemetry for months.
     */
    it('reports what it dropped rather than answering 202 in silence', async () => {
      const res = await fetch(`${app.url}/ingest/client`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://app.example' },
        body: JSON.stringify({
          samples: [
            { app: 'hub-web', kind: 'page_load' },
            { app: 'hub-web', kind: 'PageLoad' },
            { kind: 'error' },
            'not-an-object',
          ],
        }),
      })
      assert.equal(res.status, 202)
      const body = (await res.json()) as { stored: number; dropped: number; reasons: Record<string, number> }
      assert.equal(body.stored, 1)
      assert.equal(body.dropped, 3)
      assert.deepEqual(body.reasons, { unknown_kind: 1, missing_app: 1, not_an_object: 1 })
    })

    /**
     * The estate's `src/lib/obs.ts` posts `{"events":[…]}` with a `type` per record. Naming that
     * exact mistake is the difference between a frontend author fixing it in a minute and it
     * surviving another quarter.
     */
    it('names the mismatch when the body is the frontends’ own obs.ts envelope', async () => {
      const res = await fetch(`${app.url}/ingest/client`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://app.example' },
        body: JSON.stringify({ events: [{ app: 'hub-web', type: 'PageLoad', message: '/x' }] }),
      })
      assert.equal(res.status, 400)
      const body = (await res.json()) as { error: { message: string } }
      assert.match(body.error.message, /"events" array/)
      assert.match(body.error.message, /reads "samples"/)
      assert.match(body.error.message, /page_load/)
      // AND the browser must be able to READ it. A 400 without this header is a bare
      // `TypeError: Failed to fetch` in the page — the very invisibility being fixed.
      assert.equal(res.headers.get('access-control-allow-origin'), 'http://app.example')
    })
  })

  /* ---------------------------------------------------------------- unknown ingest paths */

  /**
   * The defect this whole area exists to make impossible: a client posting to an ingest path that
   * is not served must be TOLD, in a reply its own browser is permitted to read.
   */
  describe('an unknown /ingest/* path', () => {
    it('answers a diagnosable 404 naming the paths that exist', async () => {
      const res = await fetch(`${app.url}/ingest/browser`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://app.example' },
        body: JSON.stringify({ events: [] }),
      })
      assert.equal(res.status, 404)
      const body = (await res.json()) as { error: { code: string; message: string; served: string[] } }
      assert.equal(body.error.code, 'unknown_ingest_path')
      assert.match(body.error.message, /POST \/ingest\/client/)
      assert.ok(body.error.served.includes('POST /ingest/client'))
    })

    it('carries the CORS header, without which the browser cannot read the diagnosis at all', async () => {
      const res = await fetch(`${app.url}/ingest/browser`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://app.example' },
        body: '{}',
      })
      assert.equal(res.headers.get('access-control-allow-origin'), 'http://app.example')
    })

    /**
     * A preflight that 404s means the POST is never sent and the diagnosis above is never
     * fetched. It has to succeed even though the path does not exist.
     */
    it('answers the preflight 204 so the POST that carries the diagnosis is actually sent', async () => {
      const res = await fetch(`${app.url}/ingest/browser`, {
        method: 'OPTIONS',
        headers: { origin: 'http://app.example', 'access-control-request-method': 'POST' },
      })
      assert.equal(res.status, 204)
      assert.equal(res.headers.get('access-control-allow-origin'), 'http://app.example')
    })

    /** Explaining the surface to a misconfigured friend, not mapping it for a stranger. */
    it('stays a bare 404 for an origin that is not on the allowlist', async () => {
      const res = await fetch(`${app.url}/ingest/browser`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
        body: '{}',
      })
      assert.equal(res.status, 404)
      assert.equal(res.headers.get('access-control-allow-origin'), null)
      const body = (await res.json()) as { error: { code: string } }
      assert.equal(body.error.code, 'not_found')
    })
  })

  /* ---------------------------------------------------------------- reads */

  describe('the request-id lookup route', () => {
    it('requires a credential', async () => {
      const res = await fetch(`${app.url}/v1/requests/k3m9p2q7r4s8t1v6`)
      assert.equal(res.status, 401)
    })

    it('returns the events and the trace link for a request id', async () => {
      await sql`
        insert into events (ts, service, source, severity, msg, request_id, trace_id)
        values (now(), 'market', 'otlp', 'error', 'boom', 'k3m9p2q7r4s8t1v6', '00112233445566778899aabbccddeeff')
      `
      const res = await fetch(`${app.url}/v1/requests/k3m9p2q7r4s8t1v6`, { headers: { 'x-lantern-token': TOKEN } })
      assert.equal(res.status, 200)
      const body = (await res.json()) as { traceId: string; traceUrl: string; events: unknown[] }
      assert.equal(body.traceId, '00112233445566778899aabbccddeeff')
      assert.equal(body.traceUrl, 'https://tempo.example/trace/00112233445566778899aabbccddeeff')
      assert.equal(body.events.length, 1)
    })
  })

  describe('the issue and event lists', () => {
    it('serves the open issues to a credentialled caller', async () => {
      await sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen) values ('fp', 's', 'error', 'boom', now(), now())`
      const res = await fetch(`${app.url}/v1/issues`, { headers: { 'x-lantern-token': TOKEN } })
      assert.equal(res.status, 200)
      const body = (await res.json()) as { issues: unknown[] }
      assert.equal(body.issues.length, 1)
    })

    it('refuses the event list without a credential', async () => {
      assert.equal((await fetch(`${app.url}/v1/events`)).status, 401)
    })
  })

  /* ---------------------------------------------------------------- misc */

  it('answers 404 for an unknown route', async () => {
    const res = await fetch(`${app.url}/nope`)
    assert.equal(res.status, 404)
  })

  it('echoes a safe request id and sets one otherwise', async () => {
    const res = await fetch(`${app.url}/livez`, { headers: { 'x-request-id': 'abc-123' } })
    assert.equal(res.headers.get('x-request-id'), 'abc-123')
  })
})
