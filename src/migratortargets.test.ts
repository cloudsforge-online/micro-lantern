/**
 * Two modules, two migration ledgers, and the assertion that keeps them apart.
 *
 * `@cloudsforge/db` records applied migrations in a table called `schema_migrations`. The name is a
 * literal in that package — `LEDGER_SQL` — and `MigrateOptions` offers no way to change it, so two
 * modules migrating ONE database write into ONE ledger keyed by `version`. Both modules number
 * their migrations from 1.
 *
 * The failure that produces is not a crash and would not be found by reading a log. Whichever
 * module runs first records versions 1..N; the second finds those rows, treats its own 1..N as
 * applied, creates nothing, and the migrator exits 0. Nothing is red until the NEXT release's
 * `assertSchemaAtLeast` refuses to serve — naming a version number, in a service, hours later.
 *
 * Nor does anything else catch it: the advisory lock is derived from the SERVICE name and the two
 * names differ, so the two runs do not even serialise against each other.
 *
 * So it is refused before a statement is issued, and this file is why that refusal is trustworthy.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { lockKeyFor } from '@cloudsforge/db'
import { addresses, assertDistinct, type Target } from './migratortargets.ts'
import { MIGRATIONS, TABLES } from './migrations.ts'
import { MIGRATIONS as ANALYTICS_MIGRATIONS, TABLES as ANALYTICS_TABLES } from './analytics/migrations.ts'

/** A DSN assembled rather than written, so this file holds no string shaped like a credential. */
function dsn(host: string, port: number | '', database: string): string {
  return ['postgres://u:p@', host, port === '' ? '' : `:${port}`, '/', database].join('')
}

function target(module: string, network: string, url: string): Target {
  return { module, network, url, migrations: [], baselineVersion: 0 }
}

describe('what a DSN addresses', () => {
  it('is the host, the port and the database, and nothing that identifies the caller', () => {
    // Two DSNs differing only in the user still address ONE ledger. Comparing whole strings would
    // call them distinct and let the collision through.
    assert.equal(
      addresses('postgres://alice:x@db.internal:5432/analytics'),
      addresses('postgres://bob:y@db.internal:5432/analytics'),
    )
  })

  it('defaults the port, because an omitted 5432 is still 5432', () => {
    assert.equal(addresses(dsn('db.internal', '', 'lantern')), addresses(dsn('db.internal', 5432, 'lantern')))
  })

  it('is case-insensitive on the host and the database name', () => {
    assert.equal(addresses(dsn('DB.Internal', 5432, 'Lantern')), addresses(dsn('db.internal', 5432, 'lantern')))
  })

  it('keeps two different databases on one server apart', () => {
    assert.notEqual(addresses(dsn('db.internal', 5432, 'lantern')), addresses(dsn('db.internal', 5432, 'analytics')))
  })

  it('never returns the credential half of the string', () => {
    // This value is put in an error message, and an error message reaches a log. The password may
    // not be in it — never redacted, simply never assembled into it.
    const address = addresses('postgres://someuser:somepassword@db.internal:5432/analytics')
    assert.ok(!address.includes('somepassword'))
    assert.ok(!address.includes('someuser'))
    assert.ok(!address.includes('@'))
  })

  it('degrades to "cannot prove" rather than refusing a DSN shape postgres.js accepts', () => {
    // A key/value connection string is not a URL. Refusing it here would break a deployment that
    // works; returning '' means this check abstains and the migration itself still fails loudly.
    assert.equal(addresses('host=db.internal dbname=lantern'), '')
  })
})

describe('the migrator refuses two modules in one database', () => {
  it('accepts the arrangement the estate actually runs', () => {
    assert.doesNotThrow(() =>
      assertDistinct([
        target('lantern', 'primary', dsn('db.internal', 5432, 'lantern')),
        target('lantern', 'testnet', dsn('db.internal', 5432, 'lantern_testnet')),
        target('analytics', 'primary', dsn('db.internal', 5432, 'analytics')),
        target('analytics', 'testnet', dsn('db.internal', 5432, 'analytics_testnet')),
      ]),
    )
  })

  it('REFUSES when the two modules name one database', () => {
    // The assertion this whole file exists for.
    assert.throws(
      () =>
        assertDistinct([
          target('lantern', 'primary', dsn('db.internal', 5432, 'telemetry')),
          target('analytics', 'primary', dsn('db.internal', 5432, 'telemetry')),
        ]),
      /both point at/,
    )
  })

  it('REFUSES it through a spelling difference, too', () => {
    assert.throws(
      () =>
        assertDistinct([
          target('lantern', 'primary', dsn('db.internal', '', 'telemetry')),
          target('analytics', 'primary', dsn('DB.internal', 5432, 'TELEMETRY')),
        ]),
      /both point at/,
    )
  })

  it("REFUSES one module's two networks pointing at one database", () => {
    // A different fault and also fatal: migrating one database twice under one ledger is at best a
    // no-op nobody asked for, and at worst two networks' rows in one place — which is the failure
    // the whole network split exists to prevent.
    assert.throws(
      () =>
        assertDistinct([
          target('analytics', 'primary', dsn('db.internal', 5432, 'analytics')),
          target('analytics', 'testnet', dsn('db.internal', 5432, 'analytics')),
        ]),
      /both point at/,
    )
  })

  it('names both offenders and the database, and no credential', () => {
    let message = ''
    try {
      assertDistinct([
        target('lantern', 'primary', 'postgres://u:hunter2@db.internal:5432/telemetry'),
        target('analytics', 'testnet', 'postgres://u:hunter2@db.internal:5432/telemetry'),
      ])
    } catch (err) {
      message = err instanceof Error ? err.message : String(err)
    }
    assert.match(message, /lantern\/primary/)
    assert.match(message, /analytics\/testnet/)
    assert.match(message, /db\.internal:5432\/telemetry/)
    assert.ok(!message.includes('hunter2'), 'the refusal must never carry the password')
  })
})

describe('the two ledgers cannot interfere even once the databases are right', () => {
  it('the modules take different advisory locks', () => {
    // Distinct locks are only SAFE because the databases are distinct — see `assertDistinct`. They
    // are asserted here because equal ones would be the other failure: one module's migration
    // waiting on the other's, forever, in a job with no output.
    assert.notEqual(lockKeyFor('lantern'), lockKeyFor('analytics'))
  })

  it("neither module applies the other module's migrations", () => {
    // The ledgers are per database; the MIGRATION SETS are per module. If these were ever the same
    // array, `assertDistinct` would pass and both databases would get both schemas.
    assert.notEqual(MIGRATIONS, ANALYTICS_MIGRATIONS)
    assert.notDeepEqual(
      MIGRATIONS.map((m) => `${m.version}:${m.name}`),
      ANALYTICS_MIGRATIONS.map((m) => `${m.version}:${m.name}`),
    )
  })

  it('and the two schemas genuinely collide, which is what makes the refusal necessary', () => {
    /*
     * ══════════════════════════════════════════════════════════════════════════════════════════
     * MEASURED, NOT ASSUMED — and it is worse than a ledger collision.
     *
     * Both modules declare a migration named `events` and one named `jobs`, and both create tables
     * of those names with different columns. So one shared database is not "two ledgers that
     * confuse each other"; it is two `create table events` racing, and then — because the ledger
     * would already record the first module's version — the SECOND module's tables never created
     * at all, with a green migrator.
     *
     * That is the concrete cost of `assertDistinct` being absent, written down where somebody
     * tempted to delete it will read it. It is also why `service-ci.yml` creates `ci_lantern_test`
     * and `ci_analytics_test` rather than pointing both at `ci_test`, and why this repository's
     * `pnpm test` needs two DSNs.
     * ══════════════════════════════════════════════════════════════════════════════════════════
     */
    const shared = [...new Set(MIGRATIONS.map((m) => m.name))].filter((name) =>
      new Set(ANALYTICS_MIGRATIONS.map((m) => m.name)).has(name),
    )
    assert.ok(
      shared.length > 0,
      'the two modules no longer declare a migration name in common. If their schemas have become ' +
        'genuinely disjoint the refusal is cheaper than it was, but do not delete it: the ledger ' +
        'is keyed on VERSION, and both modules still number from 1.',
    )
    const sharedTables = TABLES.filter((table) => (ANALYTICS_TABLES as readonly string[]).includes(table))
    assert.ok(
      sharedTables.length > 0,
      'the two modules no longer own a table of the same name — see the note above before relaxing anything',
    )
  })

  it('and the detector is looking at real migration sets', () => {
    // Two empty arrays would satisfy every assertion above.
    assert.ok(MIGRATIONS.length > 0, 'lantern declares migrations')
    assert.ok(ANALYTICS_MIGRATIONS.length > 0, 'analytics declares migrations')
    // Both number from 1, which is exactly why one ledger could not hold both.
    assert.equal(Math.min(...MIGRATIONS.map((m) => m.version)), 1)
    assert.equal(Math.min(...ANALYTICS_MIGRATIONS.map((m) => m.version)), 1)
  })
})
