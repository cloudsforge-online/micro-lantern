/**
 * The schema.
 *
 * The migrator is exercised as a migrator, on an empty database, exactly as a deploy runs it. The
 * constraints this repository turns on — the two `issues_*_has_time` CHECKs, the trace-id shape
 * guards, the status-code range — only exist because that job ran, so a fixture schema would let
 * them drift out of the tests meant to prove they fire.
 */

import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import type postgres from 'postgres'
import { assertSchemaAtLeast, checksumOf, type Sql } from '@cloudsforge/db'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION, TABLES } from './migrations.ts'
import { db, migrateTestDb, openDb, skip } from './testsupport.ts'

describe('the migration list', () => {
  it('is numbered from one with no gaps', () => {
    assert.deepEqual(
      MIGRATIONS.map((migration) => migration.version),
      MIGRATIONS.map((_migration, index) => index + 1),
    )
  })

  it('names every migration', () => {
    for (const migration of MIGRATIONS) assert.ok(migration.name.length > 0)
  })

  it('has no duplicate names', () => {
    const names = MIGRATIONS.map((migration) => migration.name)
    assert.equal(new Set(names).size, names.length)
  })

  it('reports the version the service asserts', () => {
    assert.equal(SCHEMA_VERSION, MIGRATIONS.length)
  })

  it('baselines at zero, because this service is new', () => {
    assert.equal(BASELINE_VERSION, 0)
  })

  it('gives every migration a stable checksum', () => {
    for (const migration of MIGRATIONS) assert.match(checksumOf(migration), /^[0-9a-f]{8}$/)
  })

  it('lists every owned table for the truncating harness', () => {
    for (const table of ['events', 'issues', 'rum_samples', 'event_rollups']) {
      assert.ok(TABLES.includes(table), `TABLES missing ${table}`)
    }
  })

})

describe('the schema as the migrator leaves it', { skip }, () => {
  let sql: postgres.Sql

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
  })

  after(async () => {
    await sql.end({ timeout: 5 })
  })

  it('reports the version the service asserts', async () => {
    await assertSchemaAtLeast(db(sql), SCHEMA_VERSION)
  })

  it('refuses to claim a version it is not at', async () => {
    await assert.rejects(assertSchemaAtLeast(db(sql), SCHEMA_VERSION + 1))
  })

  it('created every owned table plus jobs', async () => {
    const rows = (await sql`
      select table_name from information_schema.tables where table_schema = 'public'
    `) as unknown as Array<{ table_name: string }>
    const names = new Set(rows.map((r) => r.table_name))
    for (const table of [...TABLES, 'jobs', 'schema_migrations']) assert.ok(names.has(table), `missing ${table}`)
  })

  it('has no user_id column on any owned table — the policy this service keeps', async () => {
    const rows = (await sql`
      select table_name, column_name from information_schema.columns
       where table_schema = 'public' and column_name = 'user_id'
    `) as unknown as Array<{ table_name: string; column_name: string }>
    assert.deepEqual([...rows], [], `a user_id column exists: ${JSON.stringify([...rows])}`)
  })

  /* ---------------------------------------------------------------- the guarantees fire */

  it('events_status_code_range refuses a status code of a thousand', async () => {
    await assert.rejects(
      sql`insert into events (ts, service, source, severity, msg, status_code) values (now(), 's', 'otlp', 'error', 'm', 1000)`,
    )
  })

  it('events_trace_id_shape refuses a wrong-length trace id', async () => {
    await assert.rejects(
      sql`insert into events (ts, service, source, severity, msg, trace_id) values (now(), 's', 'otlp', 'error', 'm', 'abc')`,
    )
  })

  it('events_severity_known refuses an unknown severity', async () => {
    await assert.rejects(
      sql`insert into events (ts, service, source, severity, msg) values (now(), 's', 'otlp', 'panicky', 'm')`,
    )
  })

  it('accepts a well-formed event', async () => {
    await sql`
      insert into events (ts, service, source, severity, msg, trace_id, status_code)
      values (now(), 's', 'otlp', 'error', 'm', '00112233445566778899aabbccddeeff', 503)
    `
    await sql`delete from events`
  })

  it('issues_resolved_has_time refuses a resolved row with no timestamp', async () => {
    await assert.rejects(
      sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status)
          values ('fp1', 's', 'error', 't', now(), now(), 'resolved')`,
    )
  })

  it('issues_regressed_has_time refuses a regressed row with no timestamp', async () => {
    await assert.rejects(
      sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen, status)
          values ('fp2', 's', 'error', 't', now(), now(), 'regressed')`,
    )
  })

  it('issues_severity_known refuses info — an issue is a fault', async () => {
    await assert.rejects(
      sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen)
          values ('fp3', 's', 'info', 't', now(), now())`,
    )
  })

  it('issues_seen_ordered refuses last_seen before first_seen', async () => {
    await assert.rejects(
      sql`insert into issues (fingerprint, service, severity, title, first_seen, last_seen)
          values ('fp4', 's', 'error', 't', now(), now() - interval '1 hour')`,
    )
  })

  it('rum_value_range refuses a duration over ten minutes', async () => {
    await assert.rejects(
      sql`insert into rum_samples (app, kind, value_ms) values ('a', 'page_load', 600001)`,
    )
  })

  it('rum_kind_known refuses an unknown kind', async () => {
    await assert.rejects(sql`insert into rum_samples (app, kind) values ('a', 'made_up')`)
  })

  it('event_rollups primary key rejects a duplicate (service, severity, bucket)', async () => {
    await sql`insert into event_rollups (service, severity, bucket, events, issues) values ('s', 'error', now(), 1, 1)`
    await assert.rejects(
      sql`insert into event_rollups (service, severity, bucket, events, issues)
          select 's', 'error', bucket, 2, 2 from event_rollups limit 1`,
    )
    await sql`delete from event_rollups`
  })
})
