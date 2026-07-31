/**
 * The leased background work, against a real Postgres — because the lease, the retention DELETE and
 * the rollup upsert are exactly the things a fake cannot prove.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import {
  GROOM_KIND,
  RECURRING,
  RETENTION_KIND,
  ROLLUP_KIND,
  groomStaleIssues,
  registerHandlers,
  rollupOnce,
  seedRecurring,
  sweepRetention,
} from './jobs.ts'
import { db, migrateTestDb, openDb, quietLogger, resetLantern, skip, testMetrics } from './testsupport.ts'

const RETENTION = { eventDays: 7, issueDays: 90, rollupDays: 400, rumDays: 30 }

describe('jobs', { skip }, () => {
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

  const jobs = (): JobsSql => sql as unknown as JobsSql

  /* ---------------------------------------------------------------- the lease */

  describe('two workers run a job once — FOR UPDATE SKIP LOCKED', () => {
    it('a single enqueued job runs exactly once across two runners', async () => {
      let runs = 0
      const handler = async (): Promise<void> => {
        runs += 1
      }
      const queueA = new JobQueue(jobs(), { owner: 'replica-a', leaseMs: 60_000 })
      const queueB = new JobQueue(jobs(), { owner: 'replica-b', leaseMs: 60_000 })
      const runnerA = new JobRunner({ queue: queueA, concurrency: 4 })
      const runnerB = new JobRunner({ queue: queueB, concurrency: 4 })
      runnerA.register('test.once', handler)
      runnerB.register('test.once', handler)

      await queueA.enqueue({ kind: 'test.once', key: 'global', payload: {} })

      // Both poll at the same time. The database lease is what stops the row being handed to two.
      await Promise.all([runnerA.tick(), runnerB.tick()])
      assert.equal(runs, 1)

      // And the row is gone — completed once.
      const left = (await sql`select count(*)::int as n from jobs where kind = 'test.once'`) as unknown as Array<{ n: number }>
      assert.equal(left[0]!.n, 0)
    })

    it('seedRecurring produces one row per recurring job even called twice', async () => {
      const queue = new JobQueue(jobs(), { owner: 'x' })
      await seedRecurring(queue)
      await seedRecurring(queue)
      const rows = (await sql`select kind, count(*)::int as n from jobs group by kind`) as unknown as Array<{ kind: string; n: number }>
      assert.equal(rows.length, RECURRING.length)
      for (const row of rows) assert.equal(row.n, 1, `duplicate ${row.kind}`)
    })
  })

  /* ---------------------------------------------------------------- retention */

  describe('retention deletes what is past its horizon', () => {
    it('deletes an event older than event retention and keeps a recent one', async () => {
      await sql`insert into events (ts, service, source, severity, msg) values (now() - interval '10 days', 's', 'otlp', 'error', 'old')`
      await sql`insert into events (ts, service, source, severity, msg) values (now(), 's', 'otlp', 'error', 'new')`
      const swept = await sweepRetention(db(sql), RETENTION)
      assert.equal(swept.events, 1)
      const rows = (await sql`select msg from events`) as unknown as Array<{ msg: string }>
      assert.deepEqual([...rows].map((r) => r.msg), ['new'])
    })

    it('deletes a rum sample past its (shorter) horizon', async () => {
      await sql`insert into rum_samples (ts, app, kind) values (now() - interval '40 days', 'a', 'page_load')`
      const swept = await sweepRetention(db(sql), RETENTION)
      assert.equal(swept.rum, 1)
    })

    it('deletes a resolved issue past the issue horizon but keeps an open one', async () => {
      await sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status, resolved_at)
                values ('r', 's', 'error', 't', now() - interval '200 days', now() - interval '200 days', 'resolved', now() - interval '200 days')`
      await sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status)
                values ('o', 's', 'error', 't', now() - interval '200 days', now() - interval '200 days', 'new')`
      const swept = await sweepRetention(db(sql), RETENTION)
      assert.equal(swept.issues, 1)
      const rows = (await sql`select fingerprint from issues`) as unknown as Array<{ fingerprint: string }>
      assert.deepEqual([...rows].map((r) => r.fingerprint), ['o'])
    })
  })

  /* ---------------------------------------------------------------- rollup */

  describe('rollup computes hourly counts', () => {
    it('rolls the current hour up by service and severity, counting distinct fingerprints', async () => {
      await sql`insert into events (ts, service, source, severity, msg, fingerprint) values (now(), 'ledger', 'otlp', 'error', 'a', 'fp1')`
      await sql`insert into events (ts, service, source, severity, msg, fingerprint) values (now(), 'ledger', 'otlp', 'error', 'b', 'fp1')`
      await sql`insert into events (ts, service, source, severity, msg, fingerprint) values (now(), 'ledger', 'otlp', 'error', 'c', 'fp2')`
      await rollupOnce(db(sql))
      const rows = (await sql`select events::int as events, issues from event_rollups where service = 'ledger' and severity = 'error'`) as unknown as Array<{ events: number; issues: number }>
      assert.equal(rows.length, 1)
      assert.equal(rows[0]!.events, 3)
      assert.equal(rows[0]!.issues, 2)
    })

    it('re-running corrects the incomplete current hour rather than duplicating', async () => {
      await sql`insert into events (ts, service, source, severity, msg) values (now(), 's', 'otlp', 'warn', 'a')`
      await rollupOnce(db(sql))
      await sql`insert into events (ts, service, source, severity, msg) values (now(), 's', 'otlp', 'warn', 'b')`
      await rollupOnce(db(sql))
      const rows = (await sql`select events::int as events from event_rollups where service = 's'`) as unknown as Array<{ events: number }>
      assert.equal(rows.length, 1)
      assert.equal(rows[0]!.events, 2)
    })
  })

  /* ---------------------------------------------------------------- groom */

  describe('grooming auto-resolves stale open issues', () => {
    it('resolves an issue whose last occurrence predates the raw-event window, stamping resolved_at', async () => {
      await sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status)
                values ('s', 's', 'error', 't', now() - interval '30 days', now() - interval '30 days', 'new')`
      const resolved = await groomStaleIssues(db(sql), RETENTION.eventDays)
      assert.equal(resolved, 1)
      const rows = (await sql`select status, resolved_at, resolved_by from issues`) as unknown as Array<{ status: string; resolved_at: Date | null; resolved_by: string | null }>
      assert.equal(rows[0]!.status, 'resolved')
      assert.ok(rows[0]!.resolved_at instanceof Date)
      assert.equal(rows[0]!.resolved_by, 'system')
    })

    it('leaves a recent open issue alone', async () => {
      await sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status)
                values ('r', 's', 'error', 't', now(), now(), 'new')`
      assert.equal(await groomStaleIssues(db(sql), RETENTION.eventDays), 0)
    })
  })

  /* ---------------------------------------------------------------- through the runner */

  describe('the handlers run through the runner', () => {
    it('registers all three recurring kinds and runs a retention sweep to completion', async () => {
      await sql`insert into events (ts, service, source, severity, msg) values (now() - interval '10 days', 's', 'otlp', 'error', 'old')`
      const queue = new JobQueue(jobs(), { owner: 'x', leaseMs: 60_000 })
      const runner = new JobRunner({ queue })
      registerHandlers(runner, { sql: db(sql), logger: quietLogger(), metrics: testMetrics(), retention: RETENTION })
      for (const kind of [RETENTION_KIND, ROLLUP_KIND, GROOM_KIND]) {
        await queue.enqueue({ kind, key: 'global', payload: {} })
      }
      // Drain every claimable job.
      while ((await runner.tick()) > 0) {
        /* keep polling until the queue is empty */
      }
      const events = (await sql`select count(*)::int as n from events`) as unknown as Array<{ n: number }>
      assert.equal(events[0]!.n, 0)
      const left = (await sql`select count(*)::int as n from jobs`) as unknown as Array<{ n: number }>
      assert.equal(left[0]!.n, 0)
    })
  })
})
