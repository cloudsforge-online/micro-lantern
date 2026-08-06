/**
 * Grouping. The product.
 *
 * A broken deploy produces thousands of lines and about four distinct problems. Showing the lines
 * is easy and nearly useless; showing the four is the job. Loki will return the 1,240 rows and
 * never tell you there are four — 13-operational-model.md is explicit that "error grouping
 * is the product; log search is the commodity", and it is the whole reason this service survives
 * the move to Loki at all.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FAILURE MODE THIS FILE EXISTS TO PREVENT: ONE GROUP PER OCCURRENCE.**
 *
 * A triage tool whose grouping explodes is worse than no triage tool. It shows a wall of issues
 * that looks like a wall of distinct problems, an operator scrolls it once, and from then on the
 * issue list is the thing nobody opens. Every rule below is there because some real message
 * carries a value that changes on every occurrence.
 *
 * The frozen service's normaliser (`stack/infra/lantern/src/fingerprint.js`) is genuinely
 * good and most of it comes forward unchanged. Two gaps are closed:
 *
 *   1. **Correlation ids were not normalised.** The frozen rules collapse UUIDs, `0x` addresses,
 *      16-plus-character hex and numbers — but this estate's own request ids are neither. The
 *      runtime's `newRequestId` (`runtime/packages/telemetry/src/index.ts`) emits sixteen
 *      characters of Crockford-ish base32, chosen precisely so a human can read one down a phone
 *      line, and its own comment at :320 says "Lantern's primary workflow is pasting one back".
 *      Sixteen characters of base32 are not hex, so `\b[0-9a-f]{16,}\b` never matched them, and a
 *      message that quotes its own request id — which the estate's error paths do — produced a NEW
 *      GROUP PER REQUEST. That is the defect, and it was one library away from the log line.
 *
 *   2. **Twelve-character hex was not matched.** A Docker short container id and a short git sha
 *      are twelve hex characters. The frozen rule's floor of sixteen let both through, so every
 *      message naming a container grouped per container and every message naming a build grouped
 *      per build.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **The rules are ordered, and the order is the substance.** Longest and most specific first: a
 * UUID contains hex runs, a timestamp contains numbers, and a URL contains an address. Reversing
 * any adjacent pair changes which rule sees the text first and therefore which placeholder ends up
 * in the hash — so the order is asserted by a test, not by convention.
 */

import { createHash } from 'node:crypto'

/** One normalisation step. Named so a test can assert on the rule that fired. */
export interface NormalRule {
  readonly name: string
  readonly pattern: RegExp
  readonly with: string
}

/**
 * The message this service can normalise before it stops trying.
 *
 * Applied BEFORE the rules rather than after: a fifty-kilobyte line is a fifty-kilobyte line to
 * every regex below, and running eleven backtracking patterns over it once per record is how an
 * ingest path becomes the outage. Two occurrences that differ only past this point group together,
 * which is the right answer anyway.
 */
export const MAX_SUBJECT = 2_000

/** The normalised form that is hashed. A cap so one enormous line cannot dominate a hash input. */
export const MAX_NORMALISED = 512

export const NORMAL_RULES: readonly NormalRule[] = Object.freeze([
  {
    name: 'uuid',
    pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    with: '<uuid>',
  },
  {
    // Before `<n>`, or the pieces of a timestamp become four separate numbers and the shape of the
    // line stops being recognisable at all.
    name: 'time',
    pattern: /\b\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?\b/g,
    with: '<time>',
  },
  {
    name: 'addr',
    pattern: /\b0x[0-9a-f]+\b/gi,
    with: '<addr>',
  },
  {
    // Twelve, not sixteen. A Docker short id and a short git sha are twelve hex characters, and
    // both appear in this estate's log lines by construction. See the header.
    name: 'hash',
    pattern: /\b[0-9a-f]{12,}\b/gi,
    with: '<hash>',
  },
  {
    // The correlation-id rule. Lowercase alnum, fourteen or more, at least two digits and at least
    // one letter — the shape of a request id, a nanoid, a Stripe-style object id.
    //
    // The bar is set where it is on purpose. It has to be low enough to catch a sixteen-character
    // base32 request id and high enough to leave identifiers alone, so:
    //
    //   * single case only, which excludes every CamelCase class name in the estate;
    //   * two digits, which excludes ordinary words and `deprecated`-style vocabulary;
    //   * fourteen characters, which excludes `postgresql16` and its relatives.
    //
    // A false positive here over-groups two distinct faults into one issue. A false negative
    // explodes one fault into an issue per occurrence. They are not symmetric: the first is an
    // operator clicking into a group and seeing two things, the second is the tool becoming
    // unusable, so the rule is tuned toward matching.
    name: 'id-lower',
    pattern: /\b(?=[a-z0-9]*[a-z])(?=(?:[a-z]*\d){2})[a-z0-9]{14,}\b/g,
    with: '<id>',
  },
  {
    // ULID and its uppercase cousins. Twenty characters is above every SCREAMING_CASE constant
    // this estate writes into a message.
    name: 'id-upper',
    pattern: /\b(?=[A-Z0-9]*[A-Z])(?=(?:[A-Z]*\d){2})[A-Z0-9]{20,}\b/g,
    with: '<id>',
  },
  {
    name: 'email',
    pattern: /\b[\w.+-]+@[\w-]+\.[\w.]+\b/g,
    with: '<email>',
  },
  {
    name: 'ip',
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g,
    with: '<ip>',
  },
  {
    // After `<ip>`, so `http://10.0.0.5:4001/x` is already `http://<ip>/x` and the whole thing
    // collapses to one placeholder either way.
    name: 'url',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s"')\]]+/gi,
    with: '<url>',
  },
  {
    // `at src/server.ts:19`. Before `<n>`, which would otherwise leave `:<n>:<n>`.
    name: 'pos',
    pattern: /:\d+:\d+\b/g,
    with: ':<pos>',
  },
  {
    name: 'number',
    pattern: /\b\d+(?:\.\d+)?(?:ms|s|ns|us|kb|mb|gb|tb|b)?\b/gi,
    with: '<n>',
  },
  {
    // Quoted values last. By this point the interesting shapes are already placeholders, and what
    // is left inside quotes is the varying part of a templated message — a column name, a key, a
    // user-supplied string. Collapsing it groups `relation "orders" does not exist` with
    // `relation "listings" does not exist`, which is one problem with the schema, not two.
    name: 'dquoted',
    pattern: /"[^"\r\n]{0,200}"/g,
    with: '"<str>"',
  },
  {
    name: 'squoted',
    pattern: /'[^'\r\n]{0,200}'/g,
    with: "'<str>'",
  },
])

/**
 * Strip the parts of a message that vary per occurrence, so that the same fault hashes the same way
 * every time.
 */
export function normalise(text: string): string {
  let out = String(text).slice(0, MAX_SUBJECT)
  for (const rule of NORMAL_RULES) {
    rule.pattern.lastIndex = 0
    out = out.replace(rule.pattern, rule.with)
    rule.pattern.lastIndex = 0
  }
  return out.replace(/\s+/g, ' ').trim().slice(0, MAX_NORMALISED)
}

/**
 * The first stack frame that is ours, which is where the fault actually is.
 *
 * A frame inside `node_modules` or `node:` internals is where the fault SURFACED. Two different
 * bugs in this estate both surface at `node:internal/process/task_queues`, and grouping on that
 * would file them together — the same explosion as the header describes, running backwards.
 */
export function topFrame(stack: string | null | undefined): string {
  if (!stack) return ''
  for (const line of String(stack).split('\n')) {
    const match = /at\s+(?:.*?\s+\()?([^()\s]+):(\d+):\d+\)?/.exec(line)
    if (!match) continue
    const file = match[1]
    const lineNo = match[2]
    if (file === undefined || lineNo === undefined) continue
    if (file.includes('node_modules') || file.startsWith('node:')) continue
    // The absolute path differs between a container, a laptop and CI, so only the part from the
    // repository root is kept. Without this, one fault groups three ways.
    return `${file.replace(/^.*\/(services|apps|packages|src)\//, '$1/')}:${lineNo}`
  }
  return ''
}

/**
 * Framework request lines that must never become issues.
 *
 * They are worth SEEING — a 5xx among them is still an error in the event stream — but every
 * service in this estate logs its own error for the same failure, so grouping these too files
 * every fault twice: once under its real cause and once under the title "request completed". Two
 * entries for one problem is the exact noise this service exists to remove. Ported verbatim in
 * intent from `stack/infra/lantern/src/fingerprint.js`.
 */
export const FRAMEWORK_LINES: ReadonlySet<string> = new Set([
  'request completed',
  'incoming request',
  'request errored',
])

/** The subset of a record grouping needs. Deliberately narrow, so a test can build one by hand. */
export interface Groupable {
  readonly service: string
  readonly severity: string
  readonly msg: string
  readonly source: string
  readonly statusCode?: number | null
  readonly errType?: string | null
  readonly errMessage?: string | null
  readonly errStack?: string | null
}

/** Is this record a fault at all? Only faults are grouped; a list padded with 404s is unread. */
export function isFault(record: Groupable): boolean {
  if (record.severity === 'error' || record.severity === 'fatal') return true
  return typeof record.statusCode === 'number' && record.statusCode >= 500
}

/**
 * The group key for a record, or `null` for anything not worth grouping.
 *
 * Four inputs, and each one earns its place:
 *
 *   `service`   two services failing the same way are two problems with two owners.
 *   `errType`   `ECONNREFUSED` and `ETIMEDOUT` reaching the same host are different faults.
 *   `subject`   the normalised message. The bulk of the discrimination.
 *   `frame`     the first frame that is ours. Two call sites raising the same error text are two
 *               bugs, and without this they would be one issue nobody could locate.
 */
export function fingerprint(record: Groupable): string | null {
  if (!isFault(record)) return null
  if (FRAMEWORK_LINES.has(record.msg) && !record.errMessage && !record.errStack) return null

  const subject = record.errMessage || record.msg || ''
  const kind = record.errType || record.source
  const frame = topFrame(record.errStack)
  const key = [record.service, kind, normalise(subject), frame].join('|')
  // sha256 truncated to sixteen hex characters. Truncation is fine here and the length is not
  // load-bearing for security: this is a grouping key, and a collision merges two issues rather
  // than authorising anything. Sixteen characters is short enough to quote in a ticket.
  return createHash('sha256').update(key).digest('hex').slice(0, 16)
}

/**
 * Human-readable one-line title for the grouped issue.
 *
 * `msg` wins over the error's own message because it is the sentence a person wrote about the
 * failure — "cannot verify tokens — identity unreachable" says what is broken, where
 * "getaddrinfo ENOTFOUND identity" only says what the socket returned. The error text is appended,
 * since it is the detail that distinguishes two faults sharing a log line.
 */
export function issueTitle(record: Groupable): string {
  const msg = record.msg && record.msg !== '(no message)' ? record.msg : ''
  const errText = record.errMessage ?? ''
  if (msg && errText && !msg.includes(errText)) return `${msg} — ${errText}`.slice(0, 300)
  if (msg) return msg.slice(0, 300)
  const type = record.errType && record.errType !== 'unstructured' ? `${record.errType}: ` : ''
  return `${type}${errText || '(no message)'}`.slice(0, 300)
}
