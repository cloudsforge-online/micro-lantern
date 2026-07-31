/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * The service this supersedes has no migration framework: `stack/infra/lantern/src/db.js:52-172` is
 * one idempotent DDL block run on every boot, from `src/index.js:13`, with no version table and no
 * advisory lock. Worse, `src/index.js:18-27` arms a `setInterval` that RETRIES that DDL every
 * fifteen seconds for as long as the database is unreachable — so a Postgres that comes back
 * during a rolling deploy is met by every replica running `CREATE TABLE` at once.
 *
 * ---------------------------------------------------------------------------------------------
 * **WHAT IS STRUCTURALLY NEW HERE, AND WHY EACH ONE EXISTS.**
 *
 *   `issues.status` EXISTS.   The frozen `issues` table has one piece of state — `resolved_at`, a
 *                             nullable timestamp (`db.js:96`). 13-operational-model.md:134 says an
 *                             issue must gain "status (`new → acknowledged → resolved →
 *                             regressed`)", and the fourth of those is the one that matters: a
 *                             resolved issue that happens again must not silently absorb the new
 *                             occurrences under a green label. The upsert in `issues.ts` moves it
 *                             to `regressed`, and the CHECK below means a row cannot claim that
 *                             state without the timestamp that says when.
 *
 *   `trace_id` AND `span_id`  13-operational-model.md:63 — "the join key is `trace_id` on every log
 *   ARE COLUMNS.              line: it is what makes 'open a Lantern issue, jump to the trace'
 *                             work." The frozen schema has no trace column at all (`db.js:60-78`),
 *                             so the two systems are two unrelated records of one event.
 *
 *   `event_rollups` EXISTS.   Events live seven days. An error-rate trend over ninety does not
 *                             come from Prometheus — it cannot downsample, which
 *                             02-target-architecture.md:501-507 records — so it is computed here,
 *                             hourly, by a leased job, into a table small enough to keep for a year.
 *
 *   `rum_samples` EXISTS,     Browser timings, as INTEGER milliseconds. Never a float: a p95 over
 *   AND ITS VALUE IS AN       stored floats cannot be audited, and every one of these numbers is a
 *   INTEGER.                  duration a browser measured in whole milliseconds anyway.
 *
 *   THERE IS NO `user_id`     11-data-and-contract-strategy.md:469 says of this service and the
 *   COLUMN, ANYWHERE.         telemetry plane: "Nothing to do — expires within 30 days, and holds
 *                             no `user_id` by policy". The frozen browser sink stores one
 *                             (`stack/infra/lantern/src/server.js:136`, `userId: item.userId`).
 *                             That is the policy being broken by the code it describes. There is no
 *                             column here to store it in, `rum.ts` drops the field at ingest, and a
 *                             test plants one and asserts it does not reach the database.
 * ---------------------------------------------------------------------------------------------
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift.
    up: JOBS_SCHEMA_SQL,
  },
  {
    version: 2,
    name: 'events',
    up: `
      -- One log line, normalised. The bulk of the data and the shortest-lived: Loki holds the raw
      -- stream (13-operational-model.md:133), so seven days here is a triage horizon rather than
      -- an archive.
      create table if not exists events (
        id            bigserial   primary key,
        -- When the producer says it happened.
        ts            timestamptz not null,
        -- When we heard about it. Separate on purpose: a container whose clock is wrong, or a
        -- collector whose queue drained late, produces a ts that is not when anything was
        -- learned. Retention prunes on ts, and an operator debugging a gap reads both.
        received_at   timestamptz not null default now(),
        -- 'service.name' from the resource, or the dev collector's container name. A metric label
        -- elsewhere, so it is bounded by the number of services rather than by anything a caller
        -- controls: 13-operational-model §13 budgets 500k active series.
        service       text        not null,
        -- otlp | client | docker. Which door the record came in by, which is the first question
        -- asked when one producer's records look wrong and another's do not.
        source        text        not null,
        severity      text        not null,
        -- The OTLP number, kept alongside the word. WARN2 and WARN4 are both 'warn' here, and the
        -- number is the only place the distinction survives.
        severity_number smallint  not null default 0,
        msg           text        not null,
        -- The human alias. 13-operational-model.md:73-78: "a user quotes an id from an error
        -- screen and an operator pastes it into one search box" — that workflow is this column
        -- and the index below it.
        request_id    text,
        -- The machine join key, to Tempo and to every other signal.
        trace_id      text,
        span_id       text,
        route         text,
        status_code   integer,
        latency_ms    integer,
        err_type      text,
        err_message   text,
        err_stack     text,
        -- Null for anything not worth grouping. See fingerprint.ts.
        fingerprint   text,
        attributes    jsonb       not null default '{}'::jsonb,

        constraint events_severity_known
          check (severity in ('trace','debug','info','warn','error','fatal')),
        -- A wrong-length trace id joins to nothing in Tempo, so it is a silent dead link rather
        -- than data. Refused at the column so that no future write path can reintroduce it.
        constraint events_trace_id_shape check (trace_id is null or trace_id ~ '^[0-9a-f]{32}$'),
        constraint events_span_id_shape  check (span_id  is null or span_id  ~ '^[0-9a-f]{16}$'),
        -- The status_code column is INTEGER and its value arrives from arbitrary JSON. 1e30 and
        -- 1.5 both satisfy Number.isFinite and both abort a batch insert with 22P02 or 22003 —
        -- the defect recorded at stack/infra/lantern/src/sanitise.js:18-20. Clamped in ingest.ts
        -- and refused here, because the clamp is a behaviour and this is a guarantee.
        constraint events_status_code_range check (status_code is null or (status_code >= 0 and status_code < 1000)),
        constraint events_latency_nonneg check (latency_ms is null or latency_ms >= 0)
      );

      create index if not exists events_ts_idx           on events (ts desc);
      create index if not exists events_service_ts_idx   on events (service, ts desc);
      create index if not exists events_severity_ts_idx  on events (severity, ts desc);
      -- Partial, because most lines carry neither. A full index on a mostly-null column is index
      -- pages of nulls that every insert still has to maintain.
      create index if not exists events_request_id_idx   on events (request_id, ts desc) where request_id is not null;
      create index if not exists events_trace_id_idx     on events (trace_id, ts) where trace_id is not null;
      create index if not exists events_fingerprint_idx  on events (fingerprint, ts desc) where fingerprint is not null;
    `,
  },
  {
    version: 3,
    name: 'issues',
    up: `
      -- The grouped error. The product: "this failure, 1,240 times, first seen 09:12" rather than
      -- 1,240 rows.
      create table if not exists issues (
        fingerprint    text        primary key,
        service        text        not null,
        severity       text        not null,
        title          text        not null,
        -- The first stack frame that is ours. Where the fault actually is, as opposed to where it
        -- surfaced. See fingerprint.ts topFrame().
        culprit        text,
        err_type       text,

        first_seen     timestamptz not null,
        last_seen      timestamptz not null,
        -- bigint, and it is a running total rather than a count of surviving rows. Events are
        -- pruned at seven days and issues at ninety; a count derived from the events table would
        -- fall to zero for an issue that is still the most important thing in the estate.
        events         bigint      not null default 0,

        -- new -> acknowledged -> resolved -> regressed. 13-operational-model.md:134.
        status         text        not null default 'new',
        assignee       text,
        runbook_url    text,
        -- The trace of the FIRST occurrence, so an issue links to the story of how it happened
        -- rather than to whichever occurrence happened to be most recent.
        first_trace_id text,

        acknowledged_at timestamptz,
        acknowledged_by text,
        resolved_at    timestamptz,
        resolved_by    text,
        regressed_at   timestamptz,

        constraint issues_status_known
          check (status in ('new','acknowledged','resolved','regressed')),
        constraint issues_severity_known check (severity in ('error','fatal','warn')),
        constraint issues_events_nonneg check (events >= 0),
        constraint issues_seen_ordered check (last_seen >= first_seen),

        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- THE TWO MOST IMPORTANT LINES IN THIS FILE.
        --
        -- A row may not claim to be resolved without saying when, and may not claim to have
        -- regressed without saying when. Both states are read by an operator deciding whether to
        -- act, and "resolved" with no timestamp is indistinguishable from "resolved by a bug in
        -- an UPDATE that forgot half its SET clause". The upsert in issues.ts sets both together;
        -- these are what make that a guarantee rather than a habit.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        constraint issues_resolved_has_time check (status <> 'resolved' or resolved_at is not null),
        constraint issues_regressed_has_time check (status <> 'regressed' or regressed_at is not null),

        constraint issues_trace_shape check (first_trace_id is null or first_trace_id ~ '^[0-9a-f]{32}$')
      );

      create index if not exists issues_last_seen_idx on issues (last_seen desc);
      -- The triage list's own query: open issues, worst first. Partial on the open set, so a year
      -- of resolved issues does not slow the page an operator actually reads.
      create index if not exists issues_open_idx
        on issues (last_seen desc)
        where status in ('new','acknowledged','regressed');
      create index if not exists issues_service_idx on issues (service, last_seen desc);
    `,
  },
  {
    version: 4,
    name: 'rum',
    up: `
      -- Browser telemetry. 13-operational-model.md:123-126: page load, first contentful paint,
      -- failed fetches and unhandled rejections, each tagged with the trace id of the request that
      -- caused it, "so the browser record and the server trace are one story".
      --
      -- THERE IS NO user_id COLUMN AND THERE WILL NOT BE ONE. See the file header.
      create table if not exists rum_samples (
        id          bigserial   primary key,
        ts          timestamptz not null default now(),
        -- The front-end that reported. Bounded by the number of apps, because it is a metric label.
        app         text        not null,
        kind        text        not null,
        route       text,
        -- INTEGER milliseconds. Never a float; see the file header.
        value_ms    integer,
        status_code integer,
        request_id  text,
        trace_id    text,
        -- A pseudonymous per-tab identifier, so two samples from one session can be joined without
        -- anything here identifying a person. Opaque to this service, and it expires with the row.
        session     text,
        attributes  jsonb       not null default '{}'::jsonb,

        constraint rum_kind_known
          check (kind in ('page_load','first_contentful_paint','largest_contentful_paint',
                          'fetch_error','unhandled_rejection','error')),
        -- A negative duration is a clock that moved backwards, and averaging one in is how a
        -- dashboard reports a page that loaded before it was requested. The ceiling is ten
        -- minutes: past that the browser was closed, not slow.
        constraint rum_value_range check (value_ms is null or (value_ms >= 0 and value_ms <= 600000)),
        constraint rum_status_range check (status_code is null or (status_code >= 0 and status_code < 1000)),
        constraint rum_trace_shape check (trace_id is null or trace_id ~ '^[0-9a-f]{32}$')
      );

      create index if not exists rum_ts_idx        on rum_samples (ts desc);
      create index if not exists rum_app_kind_idx  on rum_samples (app, kind, ts desc);
      create index if not exists rum_trace_idx     on rum_samples (trace_id) where trace_id is not null;
      create index if not exists rum_request_idx   on rum_samples (request_id) where request_id is not null;
    `,
  },
  {
    version: 5,
    name: 'rollups',
    up: `
      -- Hourly counts, by service and severity. This table is why seven-day event retention is
      -- affordable: the raw lines answer "what happened at 09:12 last Tuesday" and are worthless a
      -- fortnight later, while the shape of the last quarter is four numbers an hour.
      --
      -- Prometheus is NOT the place for this. 02-target-architecture.md:501-507 records that it
      -- cannot downsample, so a 400-day error-rate trend is either this table or nothing.
      create table if not exists event_rollups (
        service   text        not null,
        severity  text        not null,
        bucket    timestamptz not null,
        events    bigint      not null,
        -- Distinct fingerprints seen in the hour. A count of PROBLEMS rather than of lines, which
        -- is the number that tells an operator whether a spike is one fault repeating or many.
        issues    integer     not null,
        constraint event_rollups_pk primary key (service, severity, bucket),
        constraint event_rollups_nonneg check (events >= 0 and issues >= 0)
      );

      create index if not exists event_rollups_bucket_idx on event_rollups (bucket desc);
    `,
  },
]

/** Every table this service owns. The truncate list for the test harness, and nothing else. */
export const TABLES: readonly string[] = Object.freeze([
  'events',
  'issues',
  'rum_samples',
  'event_rollups',
])

/**
 * The version `index.ts` asserts before it serves.
 *
 * Derived rather than written down, so adding a migration cannot leave the assertion behind — the
 * failure that produces is a service running happily against a schema missing the CHECK it depends
 * on, which is silent until the day it matters.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce(
  (highest, migration) => Math.max(highest, migration.version),
  0,
)

/**
 * No baseline. This service's tables are created by migration 2 onward on an empty database; there
 * is no pre-existing schema to adopt, because the frozen service's `events`/`issues` tables carry
 * neither the trace columns nor the status ladder and are not the same tables.
 */
export const BASELINE_VERSION = 0
