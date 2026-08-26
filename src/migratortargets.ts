/**
 * What the migrator migrates, and the one thing it refuses to do.
 *
 * Split out of `migrator.ts` because that file is a SCRIPT — it opens pools and calls
 * `process.exit` at import — so nothing there can be tested. The rule below is the one piece of
 * this process worth testing, so it lives where a test can call it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THE DISTINCTNESS CHECK EXISTS AT ALL.**
 *
 * `@cloudsforge/db` records applied migrations in a table called `schema_migrations`. The name is a
 * literal in that package and takes no option, so two modules migrating one database write into ONE
 * ledger keyed by `version` — and both modules number their migrations from 1.
 *
 * The failure is not a crash. Whichever module runs first records versions 1..N; the second then
 * finds those rows and treats its OWN 1..N as already applied, so its tables are never created and
 * the migrator exits 0. The deploy goes green and the service refuses to serve at the next boot's
 * schema assertion, naming a version rather than the cause. Where the checksums happen to differ it
 * is louder but not clearer — "migration 5 was modified after it was applied" is a true sentence
 * about the wrong database.
 *
 * Nothing downstream can catch it, either: the advisory locks are derived from the SERVICE name and
 * the two names differ, so the two runs do not even serialise against each other.
 *
 * So it is refused here, before a statement is issued, by comparing what a DSN actually addresses.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Migration } from '@cloudsforge/db'

/** One database to migrate, and the module whose schema it holds. */
export interface Target {
  /** The module's service name. Names the advisory lock; two modules must not share one. */
  readonly module: string
  /** `primary` or `testnet`, for the log line. */
  readonly network: string
  readonly url: string
  readonly migrations: readonly Migration[]
  readonly baselineVersion: number
}

/**
 * What a connection string addresses: host, port and database name, lowercased.
 *
 * Credentials and query parameters are deliberately dropped — two DSNs differing only in the user
 * they connect as still address ONE ledger — and dropping them is also what keeps this function
 * safe to put a value from it in an error message. **Nothing here may ever be logged with the
 * password still in it**, which is the reason this returns a triple rather than the URL.
 */
export function addresses(url: string): string {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    // Not a URL this can compare. Refusing here would break a DSN shape postgres.js accepts and
    // this does not, so it degrades to "cannot prove these are the same", which is what an
    // unparseable string honestly is. The migration itself will still fail loudly if it is wrong.
    return ''
  }
  const port = parsed.port || '5432'
  const database = parsed.pathname.replace(/^\//, '')
  return `${parsed.hostname.toLowerCase()}:${port}/${database.toLowerCase()}`
}

/**
 * Refuse a target list in which two MODULES point at one database.
 *
 * Two targets of the SAME module sharing an address is a different (and also wrong) thing — the
 * mainnet and testnet DSNs being identical — and it is refused too, because migrating one database
 * twice under one ledger is at best a no-op nobody asked for and at worst two networks' rows in one
 * place, which is the failure the whole network split exists to prevent.
 */
export function assertDistinct(targets: readonly Target[]): void {
  const seen = new Map<string, Target>()
  for (const target of targets) {
    const address = addresses(target.url)
    if (address === '') continue
    const clash = seen.get(address)
    if (clash) {
      throw new Error(
        `${clash.module}/${clash.network} and ${target.module}/${target.network} both point at ` +
          `${address}. Each module keeps its own migration ledger in a table called ` +
          `schema_migrations, so one database cannot hold two — the second module's tables would ` +
          `be silently skipped and the migrator would still exit 0.`,
      )
    }
    seen.set(address, target)
  }
}
