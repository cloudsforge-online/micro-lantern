/**
 * Credentials are removed at ingest, before anything is persisted.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FROZEN SERVICE HAS NO SCRUBBING AT ALL, AND THAT IS THE SINGLE WORST THING ABOUT IT.**
 *
 * `stack/infra/lantern/src/sanitise.js` is named as though it did this. It does not: it strips
 * U+0000, clamps `status_code` to something an INTEGER column can hold and rejects
 * a NaN latency. Every one of those is about what Postgres will accept, not about what
 * Lantern should keep. A grep of that entire repository for `redact`, `scrub`, `secret`, `bearer`
 * or `password` finds the word only in comments about the service's own `LANTERN_TOKEN`.
 *
 * So the frozen service stores, in plain text, every credential any service in the estate has ever
 * written to a log line — and it stores them for seven days in a table that a single
 * `authMode() === 'open'` deployment serves to anyone who can reach port 4010. An `Authorization`
 * header logged once by a misconfigured middleware is a bearer token sitting in
 * `events.raw`, `events.msg`, `events.fields` and, through the group title, in `issues.title`.
 *
 * **Scrubbing happens BEFORE persistence, never at render.** Redacting on the way out means the
 * secret is in the database, in its backups, in the nightly dump named at
 * 13-operational-model.md, and in the reach of every future read path anyone adds. There is
 * exactly one way to not store a secret, and it is to not store it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **Why this is not merely the collector's job.** The collector already drops `authorization`,
 * `cookie` and `set-cookie` and any key matching `/token|secret|password|mnemonic|private_key|seed/`
 * (13-operational-model.md, implemented at `deploy/otel/collector.yaml` `attributes/redact`).
 * That handles ATTRIBUTES. It cannot handle a credential in the message BODY — `log.error('upstream
 * refused: Authorization: Bearer eyJhbGciOi…')` is one string to a processor that redacts by key —
 * and it does not run at all on the two paths that reach this service without passing through it:
 * the browser RUM sink and the development Docker collector. Defence in depth is the reason, and
 * "the layer above already does it" is the reason every one of those layers was skipped.
 *
 * **The replacement is a CONSTANT, and that matters for grouping.** Every match becomes
 * `[redacted:<kind>]` with no per-occurrence content, so two occurrences of one fault whose only
 * difference was the token in them normalise to the same string and land in the same issue. A
 * scrubber that replaced with a hash would be the fingerprint-explosion defect wearing a security
 * badge.
 */

/** What a redaction replaces its match with. Constant by kind — see the header. */
export type SecretKind =
  | 'authorization'
  | 'cookie'
  | 'jwt'
  | 'api-key'
  | 'aws-key'
  | 'dsn-password'
  | 'private-key'
  | 'sensitive-key'

export const REDACTED = (kind: SecretKind): string => `[redacted:${kind}]`

/** Every kind, for the metric registration and for the tests that assert the set is complete. */
export const SECRET_KINDS: readonly SecretKind[] = Object.freeze([
  'authorization',
  'cookie',
  'jwt',
  'api-key',
  'aws-key',
  'dsn-password',
  'private-key',
  'sensitive-key',
])

export interface Redaction {
  readonly kind: SecretKind
  readonly pattern: RegExp
  /** Given the match, produce the replacement. Some keep a harmless prefix; most keep nothing. */
  readonly replace: (...groups: string[]) => string
}

/**
 * A key name that means the value beside it is a credential, whatever the value looks like.
 *
 * The same list as the collector's `attributes/redact` (13-operational-model.md), plus the
 * shapes that appear in this estate's own logs. It is applied to attribute KEYS and to `key=value`
 * and `"key": "value"` inside message text, because a secret written into a sentence is still a
 * secret.
 */
export const SENSITIVE_KEY =
  /(?:^|[._-])(?:authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|passwd|pwd|passphrase|mnemonic|private[_-]?key|privkey|seed|api[_-]?key|apikey|client[_-]?secret|credential|credentials|session[_-]?key|signing[_-]?secret|cookie|set[_-]?cookie)(?:$|[._-])/i

/**
 * The value patterns, in order. **Order is load-bearing**: a bearer token is also a JWT, and the
 * `authorization` rule must eat the whole header — including the word `Bearer` — before the JWT
 * rule sees the payload, or the output reads `Authorization: Bearer [redacted:jwt]` and confirms
 * to a reader that a bearer token was there. Same for a DSN, whose password would otherwise be
 * matched by nothing at all.
 */
export const REDACTIONS: readonly Redaction[] = Object.freeze([
  {
    // `Authorization: Bearer …`, `authorization=Basic …`, and the same header without a scheme.
    // The scheme is deliberately consumed: naming it narrows a brute force to one algorithm.
    kind: 'authorization',
    pattern:
      /\b(authorization|proxy-authorization)\b\s*[:=]\s*"?(?:bearer|basic|digest|token|apikey)?\s*[A-Za-z0-9._~+/=-]{8,}"?/gi,
    replace: (header: string) => `${header}: ${REDACTED('authorization')}`,
  },
  {
    // `Set-Cookie: session=…; Path=/` — the whole value, to the end of the line. A cookie's
    // attributes are not worth the risk of a partial rule leaving the value beside them.
    kind: 'cookie',
    pattern: /\b(set-cookie|cookie)\b\s*[:=]\s*[^\r\n]+/gi,
    replace: (header: string) => `${header}: ${REDACTED('cookie')}`,
  },
  {
    // A PEM block, from BEGIN to END inclusive. `[\s\S]` rather than `.` with the `s` flag so the
    // intent survives a reader who does not know what `s` does.
    kind: 'private-key',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replace: () => REDACTED('private-key'),
  },
  {
    // A compact JWS: three base64url segments, the first of which decodes to a JSON header. The
    // `eyJ` prefix is `{"` in base64url and is what makes this specific rather than a rule that
    // eats every dotted identifier in the estate.
    kind: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g,
    replace: () => REDACTED('jwt'),
  },
  {
    // AWS access key ids. Fixed shape, and the id is enough on its own to identify an account.
    kind: 'aws-key',
    pattern: /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g,
    replace: () => REDACTED('aws-key'),
  },
  {
    // The prefixed API keys this estate and its dependencies actually issue. A prefix list rather
    // than "any long random string": the latter matches a git sha, a container id and a nonce, and
    // a scrubber that eats identifiers destroys the traceability the service exists to provide.
    kind: 'api-key',
    pattern:
      /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}|\b(?:sk|pk)-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{16,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bxox[baprs]-[A-Za-z0-9-]{8,}|\bglpat-[A-Za-z0-9_-]{16,}|\bAIza[0-9A-Za-z_-]{30,}|\bnpm_[A-Za-z0-9]{30,}/g,
    replace: () => REDACTED('api-key'),
  },
  {
    // A connection string carrying its password. The scheme, the user and the host all survive —
    // they are what makes the line worth keeping — and only the password is replaced.
    //
    // This is the one rule that must NOT eat its whole match: `postgres://[redacted]` would lose
    // which database a service could not reach, which is the entire content of the log line.
    kind: 'dsn-password',
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:/@"']{1,128}):([^\s@"']{1,256})@/gi,
    replace: (scheme: string, user: string) => `${scheme}${user}:${REDACTED('dsn-password')}@`,
  },
  {
    // `password=hunter2`, `"apiKey": "…"`, `--secret hunter2`. Applied last, so a value that a
    // sharper rule above already recognised is already gone.
    //
    // The key is preserved and the value is not: knowing that a line mentioned `client_secret` is
    // useful when reading it, and knowing the secret is not.
    kind: 'sensitive-key',
    pattern:
      /\b([A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|passphrase|mnemonic|private_key|privkey|seed|api_?key|credential|session_key)[A-Za-z0-9_.-]*)\b(\s*[:=]\s*)"?([^\s,;"'})\]]{1,512})"?/gi,
    replace: (key: string, separator: string) => `${key}${separator}${REDACTED('sensitive-key')}`,
  },
])

export interface ScrubResult<T> {
  readonly value: T
  /** How many matches of each kind were removed. Empty when the input was clean. */
  readonly removed: ReadonlyMap<SecretKind, number>
}

function bump(into: Map<SecretKind, number>, kind: SecretKind, by = 1): void {
  into.set(kind, (into.get(kind) ?? 0) + by)
}

/**
 * Scrub one string.
 *
 * Every rule is applied to the whole string, in order, so a line carrying two different kinds of
 * credential loses both. The rules are `g`-flagged and `RegExp.prototype.replace` resets `lastIndex`
 * for a global pattern on each call, so there is no cross-call state to leak between records — a
 * bug that would make the FIRST line after a match get scrubbed from the wrong offset, which is the
 * kind of thing that only shows up under load.
 */
export function scrubString(input: string): ScrubResult<string> {
  const removed = new Map<SecretKind, number>()
  let out = input
  for (const rule of REDACTIONS) {
    if (!rule.pattern.test(out)) {
      rule.pattern.lastIndex = 0
      continue
    }
    rule.pattern.lastIndex = 0
    out = out.replace(rule.pattern, (...args: unknown[]) => {
      bump(removed, rule.kind)
      // `replace` passes (match, ...groups, offset, string). The groups are what the rules want,
      // and every rule declares how many it reads, so the tail is dropped rather than guessed at.
      const groups = args.slice(1, -2).map((g) => (typeof g === 'string' ? g : ''))
      return rule.replace(...groups)
    })
    rule.pattern.lastIndex = 0
  }
  return { value: out, removed }
}

/** Merge one result's counters into an accumulator. */
export function mergeRemoved(
  into: Map<SecretKind, number>,
  from: ReadonlyMap<SecretKind, number>,
): void {
  for (const [kind, count] of from) bump(into, kind, count)
}

/**
 * Scrub a structured attribute tree.
 *
 * Three things happen, and the second is the one the collector cannot do for us:
 *
 *   1. Every string VALUE goes through `scrubString`.
 *   2. A value whose KEY is sensitive is replaced wholesale, whatever its type. A number is a
 *      plausible PIN and an object is a plausible credentials bag; a rule that only looked at
 *      strings would keep both.
 *   3. Keys are scrubbed too. A key is attacker-influenced on the RUM path, and a caller who can
 *      name a key can put a token in the name.
 *
 * `depth` is bounded by the caller's limit before this is reached (see `otlp.ts`), so this walks a
 * structure that is already known to be shallow.
 */
export function scrubValue(value: unknown, removed: Map<SecretKind, number>, sensitiveKey = false): unknown {
  if (sensitiveKey) {
    // Counted once for the whole subtree rather than once per leaf: an operator reading
    // `lantern_secrets_redacted_total` wants the number of secrets, not the number of JSON nodes
    // one secret happened to occupy.
    if (value !== undefined && value !== null) bump(removed, 'sensitive-key')
    return REDACTED('sensitive-key')
  }
  if (typeof value === 'string') {
    const result = scrubString(value)
    mergeRemoved(removed, result.removed)
    return result.value
  }
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map((entry) => scrubValue(entry, removed))
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const cleanKey = scrubString(key)
    mergeRemoved(removed, cleanKey.removed)
    out[cleanKey.value] = scrubValue(entry, removed, SENSITIVE_KEY.test(key))
  }
  return out
}

/** Is this attribute key one whose value must never be stored? Exported for the ingest tests. */
export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key)
}
