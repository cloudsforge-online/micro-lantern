/**
 * The grouped issue, and the status ladder.
 *
 * `fingerprint.ts` decides WHICH group a record belongs to; this decides what happens to the group
 * row when another occurrence arrives. The whole of the status ladder that
 * 13-operational-model.md asks for — `new → acknowledged → resolved → regressed` — lives in the
 * one upsert below.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A RESOLVED ISSUE THAT HAPPENS AGAIN MUST NOT SILENTLY ABSORB THE NEW OCCURRENCES.**
 *
 * The frozen `issues` table has one piece of state, a nullable `resolved_at` (`db.js`), so an
 * occurrence after a resolve just bumps `last_seen` under a green label and nobody is told the
 * fault came back. Here, an occurrence whose `last_seen` is past the `resolved_at` moves the row to
 * `regressed` and stamps `regressed_at` in the SAME statement — and `issues_regressed_has_time`
 * (migration 3) refuses a row that claims to have regressed without saying when, so the stamp is a
 * guarantee rather than a habit.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Sql } from '@cloudsforge/db'
import { issueTitle, topFrame, type Groupable } from './fingerprint.ts'

/** `issues.severity` is CHECKed to this set; a fault logged at `info` (a 5xx) still needs one. */
export type IssueSeverity = 'error' | 'fatal' | 'warn'

/**
 * Map a record's severity onto the issue vocabulary.
 *
 * A record can be a fault by status code while carrying any severity — a 500 logged at `info` is
 * the common case — and `issues_severity_known` would refuse `info`. Such a record becomes an
 * `error` issue: it IS an error, whatever the line called itself.
 */
export function issueSeverityOf(record: Groupable): IssueSeverity {
  if (record.severity === 'fatal') return 'fatal'
  if (record.severity === 'warn') return 'warn'
  return 'error'
}

export interface IssueUpsert {
  readonly fingerprint: string
  readonly service: string
  readonly severity: IssueSeverity
  readonly title: string
  readonly culprit: string | null
  readonly errType: string | null
  readonly firstSeen: Date
  readonly lastSeen: Date
  /** Occurrences in THIS batch. Added to the running total; never a count of surviving rows. */
  readonly events: number
  readonly firstTraceId: string | null
}

/** Build the upsert shape from a representative record of the group and its aggregated span. */
export function issueFrom(
  record: Groupable,
  fingerprint: string,
  firstSeen: Date,
  lastSeen: Date,
  events: number,
  firstTraceId: string | null,
): IssueUpsert {
  return {
    fingerprint,
    service: record.service,
    severity: issueSeverityOf(record),
    title: issueTitle(record),
    culprit: topFrame(record.errStack) || null,
    errType: record.errType ?? null,
    firstSeen,
    lastSeen,
    events,
    firstTraceId,
  }
}

/**
 * Upsert one issue.
 *
 * `first_seen` and `first_trace_id` are set on insert and never overwritten — an issue links to the
 * story of how it FIRST happened, not to whichever occurrence was most recent. `events` accumulates
 * a running total, because events are pruned at seven days and issues at ninety: a count derived
 * from the events table would fall to zero for an issue that is still the most important thing in
 * the estate.
 */
export async function upsertIssue(sql: Sql, issue: IssueUpsert): Promise<void> {
  await sql`
    insert into issues
      (fingerprint, service, severity, title, culprit, err_type, first_seen, last_seen, events, first_trace_id)
    values
      (${issue.fingerprint}, ${issue.service}, ${issue.severity}, ${issue.title}, ${issue.culprit},
       ${issue.errType}, ${issue.firstSeen}, ${issue.lastSeen}, ${issue.events}, ${issue.firstTraceId})
    on conflict (fingerprint) do update set
      last_seen  = greatest(issues.last_seen, excluded.last_seen),
      first_seen = least(issues.first_seen, excluded.first_seen),
      events     = issues.events + excluded.events,
      severity   = excluded.severity,
      title      = excluded.title,
      culprit    = coalesce(excluded.culprit, issues.culprit),
      err_type   = coalesce(excluded.err_type, issues.err_type),
      -- The regression transition, and the stamp the CHECK requires, set together.
      status = case
        when issues.status = 'resolved' and excluded.last_seen > issues.resolved_at then 'regressed'
        else issues.status end,
      regressed_at = case
        when issues.status = 'resolved' and excluded.last_seen > issues.resolved_at then now()
        else issues.regressed_at end
  `
}

export interface IssueRow {
  readonly fingerprint: string
  readonly service: string
  readonly severity: string
  readonly title: string
  readonly culprit: string | null
  readonly status: string
  readonly events: string
  readonly first_seen: Date
  readonly last_seen: Date
  readonly first_trace_id: string | null
}

/** The triage list: open issues, worst-recent first. Backed by the partial `issues_open_idx`. */
export async function listOpenIssues(sql: Sql, limit = 100): Promise<readonly IssueRow[]> {
  return (await sql`
    select fingerprint, service, severity, title, culprit, status,
           events::text as events, first_seen, last_seen, first_trace_id
      from issues
     where status in ('new','acknowledged','regressed')
     order by last_seen desc
     limit ${limit}
  `) as unknown as IssueRow[]
}

/** Open issues counted by severity, for the `/metrics` gauge. Bounded by the number of faults. */
export async function openIssueCounts(sql: Sql): Promise<ReadonlyMap<string, number>> {
  const rows = (await sql`
    select severity, count(*)::int as n
      from issues
     where status in ('new','acknowledged','regressed')
     group by severity
  `) as unknown as Array<{ severity: string; n: number }>
  return new Map(rows.map((row) => [row.severity, row.n]))
}
