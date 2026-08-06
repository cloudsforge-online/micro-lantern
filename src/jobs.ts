/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no `setInterval`
 * in this repository doing domain work, and CI greps for one.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS FILE REPLACES THE FROZEN SERVICE'S TWO MODULE-SCOPE TIMERS, AND THAT IS THE POINT.**
 *
 * The service this supersedes flushes its write buffer on a `setInterval` (`store.js`) and re-runs
 * its whole DDL on another (`index.js`). Both are per-process state, so two replicas do the
 * work twice: two flushes racing on the same rows, two `CREATE TABLE`s at once when Postgres comes
 * back mid-deploy. Each job here is claimed `FOR UPDATE SKIP LOCKED` under a lease keyed `global`,
 * so with N replicas each tick runs exactly once — the retention DELETE runs once, the rollup
 * upsert runs once, the auto-resolve runs once.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Rollup re-runs over the last few hours on purpose: the current hour is incomplete every time it
 * is written, so the upsert has to CORRECT it rather than assume it is final. `event_rollups` is
 * why seven-day event retention is affordable — Prometheus cannot downsample
 * (02-target-architecture.md), so a 400-day error-rate trend is this table or nothing.
 */

import { type JobQueue, type JobRunner, type RunnerEvent } from '@cloudsforge/jobs'
import type { Sql } from '@cloudsforge/db'
import type { Logger, Metrics } from '@cloudsforge/telemetry'

export const RETENTION_KIND = 'retention'
export const ROLLUP_KIND = 'rollup'
export const GROOM_KIND = 'issue.groom'

export interface Recurring {
  readonly kind: string
  readonly key: string
  readonly everyMs: number
}

/** Every recurring job. The key is `global` because each contends on deletions or an upsert. */
export const RECURRING: readonly Recurring[] = Object.freeze([
  { kind: ROLLUP_KIND, key: 'global', everyMs: 300_000 },
  { kind: RETENTION_KIND, key: 'global', everyMs: 3_600_000 },
  { kind: GROOM_KIND, key: 'global', everyMs: 3_600_000 },
])

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep', payload: {} })
  }
}

/**
 * Re-arm a recurring job from its completion event — the only moment the row is gone. A
 * dead-lettered recurring job is deliberately NOT re-armed: the row stays, `jobs_dead_total`
 * climbs, and that is how an operator learns the thing scheduling everything else has stopped.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKey = new Map(RECURRING.map((job) => [`${job.kind} ${job.key}`, job]))
  return (event) => {
    if (event.type !== 'completed' || !event.kind || !event.key) return
    const job = byKey.get(`${event.kind} ${event.key}`)
    if (!job) return
    void queue
      .enqueue({
        kind: job.kind,
        key: job.key,
        runAt: new Date(Date.now() + job.everyMs),
        onConflict: 'earliest',
        payload: {},
      })
      .catch((err: unknown) => logger.error('failed to re-arm recurring job', { kind: job.kind, err }))
  }
}

export interface Retention {
  readonly eventDays: number
  readonly issueDays: number
  readonly rollupDays: number
  readonly rumDays: number
}

export interface JobDeps {
  readonly sql: Sql
  readonly logger: Logger
  readonly metrics: Metrics
  readonly retention: Retention
  readonly now?: () => Date
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  /* ---------------------------------------------------------------- rollup */

  runner.register(ROLLUP_KIND, async (_job, _ctx) => {
    await rollupOnce(deps.sql)
  })

  /* ---------------------------------------------------------------- retention */

  runner.register(RETENTION_KIND, async (_job, _ctx) => {
    const deleted = await sweepRetention(deps.sql, deps.retention)
    deps.logger.info('retention sweep', { ...deleted })
  })

  /* ---------------------------------------------------------------- issue.groom */

  runner.register(GROOM_KIND, async (_job, _ctx) => {
    // Auto-resolve the open issues that can no longer recur within the RAW event window: once an
    // issue's last occurrence is older than event retention, nothing left in `events` can bump it,
    // so leaving it open is leaving noise on the triage list. `resolved_at` is stamped in the same
    // statement, which is what `issues_resolved_has_time` requires.
    const resolved = await groomStaleIssues(deps.sql, deps.retention.eventDays)
    if (resolved > 0) deps.logger.info('auto-resolved stale issues', { resolved })
  })

  return runner
}

/** Upsert hourly rollups over the last few hours. Exported so a test can drive it directly. */
export async function rollupOnce(sql: Sql): Promise<void> {
  await sql`
    insert into event_rollups (service, severity, bucket, events, issues)
    select service,
           severity,
           date_trunc('hour', ts)                                     as bucket,
           count(*)::bigint                                           as events,
           count(distinct fingerprint) filter (where fingerprint is not null)::int as issues
      from events
     where ts >= date_trunc('hour', now() - interval '3 hours')
     group by service, severity, bucket
    on conflict (service, severity, bucket) do update set
      events = excluded.events, issues = excluded.issues
  `
}

export interface SweepResult {
  readonly events: number
  readonly rum: number
  readonly rollups: number
  readonly issues: number
}

/** Delete everything past its retention horizon. Each table on its own column — see migrations. */
export async function sweepRetention(sql: Sql, retention: Retention): Promise<SweepResult> {
  const events = await del(sql`delete from events where ts < now() - make_interval(days => ${retention.eventDays})`)
  const rum = await del(sql`delete from rum_samples where ts < now() - make_interval(days => ${retention.rumDays})`)
  const rollups = await del(
    sql`delete from event_rollups where bucket < now() - make_interval(days => ${retention.rollupDays})`,
  )
  // Only resolved issues expire on the issue horizon: an open issue outlives its events by design,
  // because it is still the most important thing in the estate even when the lines behind it are
  // long gone.
  const issues = await del(sql`
    delete from issues
     where status = 'resolved'
       and last_seen < now() - make_interval(days => ${retention.issueDays})
  `)
  return { events, rum, rollups, issues }
}

/** Auto-resolve issues whose last occurrence predates the raw-event window. Returns the count. */
export async function groomStaleIssues(sql: Sql, eventDays: number): Promise<number> {
  return del(sql`
    update issues
       set status = 'resolved', resolved_at = now(), resolved_by = 'system'
     where status in ('new','acknowledged','regressed')
       and last_seen < now() - make_interval(days => ${eventDays})
  `)
}

/** Refresh the queue-depth gauges. Called at scrape time, never on a timer. */
export async function sampleQueue(queue: JobQueue, metrics: Metrics): Promise<void> {
  const stats = await queue.stats()
  metrics.set('jobs_pending', stats.pending)
  metrics.set('jobs_overdue', stats.overdue)
}

/** postgres.js returns a result whose `count` is the affected-row count for a write. */
async function del(promise: Promise<unknown>): Promise<number> {
  const result = (await promise) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}
