/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable this service reads is named here and
 * nowhere else.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THREE VARIABLES IN THE FROZEN SERVICE DEFAULT TO A MODE THAT SHOULD NOT EXIST, AND ALL THREE
 * ARE REQUIRED HERE.**
 *
 * `stack/infra/lantern/src/env.js,43` default `NIMBUS_JWKS_URL` and `LANTERN_TOKEN` to the
 * empty string, and `src/auth.js,42` turns that pair of empty strings into
 * `authMode() === 'open'` — which returns `{ ok: true }` for every request before any credential is
 * examined. The service then logs a warning at boot (`src/server.js`) and serves every log line
 * in the estate to anyone who can reach the port. A credential whose absence is a supported mode is
 * a credential nobody notices is absent, and a warning at boot is read once, on the day it is
 * deployed, by the person who already knows.
 *
 * `LANTERN_TOKEN` is required here, and its SHAPE is asserted by `@cloudsforge/secrets` rather than
 * its length — see the block above `requiredOpaqueSecret` for why the length floor that used to
 * stand here could not fail for the value this estate actually shipped.
 *
 * The third is `LANTERN_DOCKER_COLLECTOR`. It defaults to OFF and it refuses to turn on outside
 * `NODE_ENV=development`, because the frozen service's PRIMARY collection path is a mounted
 * `/var/run/docker.sock` (`src/env.js`, `src/docker.js`) — and a container with the Docker
 * socket mounted is a container with root on the host. It can create a privileged container with
 * `/` bind-mounted. 13-operational-model.md demotes it to "a dev fallback behind
 * `LANTERN_DOCKER_COLLECTOR`, off outside `dev`"; this is that sentence, enforced.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Two behaviours are copied deliberately from the siblings:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic, and a placeholder that boots is a placeholder that reaches production.
 */

import { hostname } from 'node:os'
import { SecretError, assertOpaqueSecret } from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a migration
 * advisory lock.
 */
export const SERVICE = 'lantern'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * THE `PLACEHOLDERS` SET THAT USED TO BE HERE IS GONE, AND ITS ABSENCE IS THE FIX.
 *
 * It held nine exact strings and was paired with a 24-character floor. Neither could fail for the
 * value that is in `deploy/compose/docker-compose.estate.yml` on two lines TODAY:
 * `LANTERN_TOKEN: estate-only-lantern-token-000000000000` is 38 characters and was on nobody's
 * list. Measured out of `cloudsforge-estate-lantern-1` on 2026-08-05, so this is not a reading of
 * the file — it is what the running container holds. Both lines are HARDCODED LITERALS rather than
 * `${LANTERN_TOKEN:-…}` interpolations, so no deploy has ever been able to override them.
 *
 * A check that cannot fail is worse than no check, because the absence of an alarm gets read as the
 * absence of a problem — and this token is the whole of the authentication on a `/metrics` surface
 * that publishes which services are producing errors and at what rate.
 *
 * A deny-list of exact strings is structurally unable to work: the next placeholder somebody writes
 * is, by definition, not on it. `@cloudsforge/secrets` asserts the SHAPE of the value instead,
 * which is the property a placeholder cannot have. It is imported rather than copied so that this
 * service cannot drift from the other sixteen.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and the
 * command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * A secret whose ALPHABET THIS ESTATE DOES NOT CONTROL.
 *
 * ── WHY `assertOpaqueSecret` AND NOT `assertGeneratedSecret` ───────────────────────────────────
 *
 * `assertGeneratedSecret` is the stricter rule and it is the right one for a key the estate MINTS —
 * the event-bus HMAC key, this service's absent-by-design signing material — because the estate
 * chooses those values with `openssl rand -base64 48` and can therefore demand the base64 or hex
 * alphabet of them.
 *
 * `LANTERN_TOKEN` is not minted by anything. Nothing in `deploy/scripts/estate-bootstrap.sh` issues
 * it; it is a static shared secret written into a compose file and into Prometheus's
 * `http_headers: files:` block by an operator, and read back out of a runbook by the person holding
 * the incident. That is the case `@cloudsforge/secrets` documents `assertOpaqueSecret` for in so
 * many words — "a break-glass token typed into a runbook" — and demanding base64 of a value a
 * human has to be able to transcribe is how a guard ends up deleted at 3am.
 *
 * ── IT REFUSES THE LIVE VALUE ANYWAY, WHICH IS THE ENTIRE POINT ────────────────────────────────
 *
 * The two rules differ on the alphabet and agree on everything that matters here. Both normalise
 * punctuation and case away and then refuse a placeholder MARKER anywhere in the value, so
 * `estate-only-lantern-token-000000000000` flattens to a string containing `estateonly` and is
 * refused by either. The choice between them buys the operator a hand-set value that works; it does
 * not buy the defect a way through.
 *
 * **CONSEQUENCE, STATED PLAINLY: this service will not boot on either estate until `LANTERN_TOKEN`
 * is set to a real value.** That is the fix, not a side effect of it — see the block above.
 */
function requiredOpaqueSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertOpaqueSecret(name, value))
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

function boolean(source: Source, name: string, fallback: boolean): boolean {
  const raw = source[name]?.trim().toLowerCase()
  if (!raw) return fallback
  if (raw === 'true' || raw === '1') return true
  if (raw === 'false' || raw === '0') return false
  throw new EnvError(`${name} must be true or false (got ${raw})`)
}

/**
 * Browser origins allowed to reach the RUM sink.
 *
 * An allowlist, never a wildcard: the RUM sink is the one route on this service that answers
 * without a credential, and a `*` there lets any page on the internet write into the triage view.
 * Empty means the sink is OFF, and off is the default — "a browser may post to us" is a decision
 * somebody makes, not a thing that happens because nobody set a variable.
 */
export function parseOrigins(raw: string): readonly string[] {
  const out: string[] = []
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    if (entry === '*') {
      throw new EnvError('LANTERN_RUM_ORIGINS may not be "*" — name the origins')
    }
    let url: URL
    try {
      url = new URL(entry)
    } catch {
      throw new EnvError(`LANTERN_RUM_ORIGINS entry "${entry}" is not an absolute origin`)
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new EnvError(`LANTERN_RUM_ORIGINS entry "${entry}" must be http or https`)
    }
    // `new URL('https://a.example/x').origin` drops the path, which is what an Origin header
    // carries. Comparing against anything else would never match.
    if (out.includes(url.origin)) throw new EnvError(`LANTERN_RUM_ORIGINS names "${url.origin}" twice`)
    out.push(url.origin)
  }
  return Object.freeze(out)
}

export interface Limits {
  /**
   * The whole request body. Past this the request is REFUSED — 413, nothing stored.
   *
   * Not truncated. A truncated protobuf is a different protobuf: cutting a length-delimited field
   * short makes the remaining bytes decode as some other field of some other type, and the record
   * that reaches the database is then a record nobody sent. The same is true of JSON, where a
   * truncated object either fails to parse or, worse, parses as a prefix that happens to be valid.
   * An ingest surface that truncates is an ingest surface an attacker can steer.
   */
  readonly maxBodyBytes: number
  /** Log records in one export. A batch larger than this is a caller that has misunderstood. */
  readonly maxRecords: number
  /** Attributes on one record. Past this the RECORD is rejected; the batch is not. */
  readonly maxAttributes: number
  /** Nesting inside an attribute value. A deeply nested value is a stack-overflow attempt. */
  readonly maxDepth: number
  /** One string value. Longer strings are clamped, and the clamp is recorded on the record. */
  readonly maxStringBytes: number
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  /**
   * The TESTNET database, when this deployment serves both networks. Empty means single-network —
   * `networkSql` then holds one handle and REFUSES a testnet request rather than answering it out
   * of mainnet rows (micro-deploy `docs/network-consolidation.md` §2.2).
   */
  readonly databaseUrlTestnet: string
  /**
   * The network to assume when a request carries no `CF-Network`, or empty to refuse. Set for
   * `pnpm dev`, which has no gateway. Never in production, where guessing makes a routing fault a
   * silent cross-network write.
   */
  readonly singleNetwork: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  readonly instanceId: string

  /**
   * The credential Prometheus and the OTel collector present in `x-lantern-token`.
   *
   * `/metrics` is authenticated, and that is a correction this estate has already recorded once:
   * 02-target-architecture.md says of the sibling that "scraping Beacon costs a credential,
   * not just a scrape config". It costs the same here and for a stronger reason — Lantern's
   * `/metrics` publishes which services are producing errors and at what rate, which is a map of
   * where the estate is weakest.
   *
   * The header name is `x-lantern-token` because that is the name the frozen service already reads
   * (`stack/infra/lantern/src/auth.js`), so a deploy that already sets it keeps working.
   */
  readonly token: string

  readonly limits: Limits

  /** Raw events. Seven days, from 11-data-and-contract-strategy.md — Loki holds the stream. */
  readonly eventRetentionDays: number
  /** Grouped issues. Ninety days: "an issue outlives its events; that is the point of grouping." */
  readonly issueRetentionDays: number
  /**
   * Hourly rollups.
   *
   * These are this service's own table and they are why the retention above is affordable.
   * Prometheus cannot downsample — 02-target-architecture.md — so an error-rate trend
   * older than the raw events has to be computed here or not at all.
   */
  readonly rollupRetentionDays: number
  readonly rumRetentionDays: number

  /** Origins allowed to POST to the RUM sink. Empty disables the sink entirely. */
  readonly rumOrigins: readonly string[]
  /** Per client address, per minute. In-process; see `rum.ts` for why that is honest. */
  readonly rumQuotaPerMinute: number

  /**
   * The dev-only Docker-socket collector. OFF, and it refuses to turn on outside development.
   * See the file header — this is the security posture of the whole service.
   */
  readonly dockerCollector: boolean
  readonly dockerSocket: string

  /**
   * Where a trace id becomes a link. Optional: a deploy without Tempo publishes no link rather
   * than a broken one, and a broken link in an incident console costs more than no link.
   */
  readonly traceUrlTemplate: string
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const nodeEnv = optional(source, 'NODE_ENV', 'development')

  const dockerCollector = boolean(source, 'LANTERN_DOCKER_COLLECTOR', false)
  if (dockerCollector && nodeEnv !== 'development') {
    // Refused rather than warned. The socket collector's three real advantages — nothing to
    // reconfigure, a dying service's last words still captured, no agent to install — are all
    // stated at 13-operational-model.md, and they are the reason it survives at all. None
    // of them is worth handing every container on the host root on the host.
    throw new EnvError(
      'LANTERN_DOCKER_COLLECTOR is a development fallback and cannot be enabled with ' +
        `NODE_ENV=${nodeEnv}: a container holding /var/run/docker.sock holds root on the host. ` +
        'Outside development, logs arrive by OTLP push from the collector.',
    )
  }

  const eventRetentionDays = integer(source, 'LANTERN_EVENT_RETENTION_DAYS', 7, 1, 400)
  const issueRetentionDays = integer(source, 'LANTERN_ISSUE_RETENTION_DAYS', 90, 1, 3_650)
  if (issueRetentionDays < eventRetentionDays) {
    // An issue that expires before the events behind it is a grouping that has been thrown away
    // while its inputs survive — the exact inversion of what this service is for. 90 over 7 is the
    // documented pair (11-data-and-contract-strategy.md) and the ordering is the point.
    throw new EnvError(
      `LANTERN_ISSUE_RETENTION_DAYS (${issueRetentionDays}) must be at least ` +
        `LANTERN_EVENT_RETENTION_DAYS (${eventRetentionDays}) — an issue outlives its events`,
    )
  }

  return {
    port: integer(source, 'PORT', 4010, 1, 65_535),
    env: nodeEnv,
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'LANTERN_DATABASE_URL'),
    databaseUrlTestnet: optional(source, 'LANTERN_DATABASE_URL_TESTNET', ''),
    singleNetwork: optional(source, 'CF_NETWORK_SINGLE', ''),
    databasePoolMax: integer(source, 'LANTERN_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),

    token: requiredOpaqueSecret(source, 'LANTERN_TOKEN'),

    limits: {
      // Four mebibytes. The collector's default `batch` produces exports well under this, and the
      // number is a ceiling on what one unauthenticated-by-network-position caller can make this
      // process allocate before it is refused.
      maxBodyBytes: integer(source, 'LANTERN_MAX_BODY_BYTES', 4 * 1024 * 1024, 1024, 64 * 1024 * 1024),
      maxRecords: integer(source, 'LANTERN_MAX_RECORDS', 5_000, 1, 100_000),
      maxAttributes: integer(source, 'LANTERN_MAX_ATTRIBUTES', 128, 1, 1_024),
      maxDepth: integer(source, 'LANTERN_MAX_DEPTH', 8, 1, 32),
      maxStringBytes: integer(source, 'LANTERN_MAX_STRING_BYTES', 8_192, 64, 262_144),
    },

    eventRetentionDays,
    issueRetentionDays,
    rollupRetentionDays: integer(source, 'LANTERN_ROLLUP_RETENTION_DAYS', 400, 1, 3_650),
    rumRetentionDays: integer(source, 'LANTERN_RUM_RETENTION_DAYS', 30, 1, 400),

    rumOrigins: parseOrigins(optional(source, 'LANTERN_RUM_ORIGINS', '')),
    rumQuotaPerMinute: integer(source, 'LANTERN_RUM_QUOTA_PER_MINUTE', 120, 1, 100_000),

    dockerCollector,
    dockerSocket: optional(source, 'LANTERN_DOCKER_SOCKET', '/var/run/docker.sock'),

    traceUrlTemplate: optional(source, 'LANTERN_TRACE_URL_TEMPLATE', ''),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and
 * the report of it.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
