# lantern

The estate's **telemetry plane**, in one process and two modules.

**lantern** takes the log lines every service emits, removes the credentials they carry, groups the
occurrences into *issues*, and answers the one question an operator actually asks — "here is a
request id off an error screen; what happened, and where is the trace?"

**analytics** — absorbed in wave M1b of micro-deploy `docs/service-merge-plan.md` — takes signed
product events off the bus, pseudonymises their subjects behind a pepper, and answers funnels,
retention cohorts and daily series with a k-anonymity floor on every cell. Its source lives under
[`src/analytics/`](src/analytics), its database is its own, and its pepper is reachable from that
directory and nowhere else. See [Two modules, one process](#two-modules-one-process).

Design authority: [`ecosystem/13-operational-model.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/13-operational-model.md)

It is a leaf. Nothing in the estate calls it, and it calls nothing at boot. Beacon failing is not a
service failure, and neither is this one.

## What it is

- **`POST /otlp/v1/logs`** — the primary ingest path. The OTel collector's `otlphttp/lantern`
  exporter posts OTLP **protobuf** here (`../deploy/otel/collector.yaml`,
  `../deploy/compose/env/otel-collector.env:24`, `../deploy/Makefile:65` set the endpoint to
  `http://lantern:4010/otlp`, and the exporter appends `/v1/logs`). The protobuf wire format is
  decoded by hand, with no dependency in the process that parses attacker-controlled bytes. JSON is
  accepted too. It is **unauthenticated by design** — the exporter presents no credential, because a
  Lantern outage must not back-pressure the log pipeline into Loki — and defended instead by size,
  record-count, attribute-count and depth limits that **refuse rather than truncate**.
- **Scrubbing before persistence.** Every free-text field and the whole attribute tree pass through
  `src/scrub.ts` before a value is bound to a statement. The replacement is a constant
  (`[redacted:<kind>]`), so two occurrences that differed only by their token group together.
- **Grouping into issues** (`src/fingerprint.ts`). A broken deploy is thousands of lines and about
  four problems; this shows the four. The normaliser collapses UUIDs, timestamps, addresses,
  request ids and short hashes so one fault is one issue, not one issue per occurrence.
- **The request-id lookup** — `GET /v1/requests/:requestId` returns the events and the Tempo trace
  link. Also `GET /v1/issues` (the triage list) and `GET /v1/events`.
- **A browser RUM / client-error sink** — `POST /ingest/client`, origin-allowlisted, per-client
  quota, no credential, and **no `user_id`**: the field is never read and there is no column for it.
  See [the browser sink contract](#the-browser-sink-contract) — a frontend that gets it wrong is
  now told so, in a reply its own browser is allowed to read.
- **`/livez`, `/readyz`, and an authenticated `/metrics`.** Scraping this plane costs a credential,
  because `/metrics` publishes which services are failing and how fast.
- **Leased background work** (`src/jobs.ts`): hourly retention sweep, five-minute rollups, and
  auto-resolve of stale issues — each claimed `FOR UPDATE SKIP LOCKED`, so two replicas do the work
  once. No `setInterval`.

## The browser sink contract

The path is **`POST /ingest/client`**, and the body is **`{"samples":[…]}`**.

This is written down because getting it wrong cost the estate every browser event it ever
generated. All sixteen frontends ship a byte-identical `src/lib/obs.ts` that posts
`{"events":[…]}` to `/ingest/browser` — a path this service does not serve, with an envelope it
does not read, carrying records keyed `type` where this service requires `kind`. Three independent
disagreements, any one of which is total data loss.

| Field | Required | Notes |
| --- | --- | --- |
| `app` | yes | The frontend's name. A metric label, so keep it bounded. |
| `kind` | yes | One of `page_load`, `first_contentful_paint`, `largest_contentful_paint`, `fetch_error`, `unhandled_rejection`, `error`. A CHECK constraint, not a suggestion — **not** a free-text `type`. |
| `route` | no | The path, not the full URL. |
| `valueMs` | no | Integer milliseconds, 0–600000. |
| `statusCode` | no | 0–999. |
| `requestId` | no | The `x-request-id` of the failed response. This is what joins a browser record to the server's logs. |
| `traceId` | no | 32 lowercase hex characters, or it is dropped. |
| `session` | no | Pseudonymous per-tab id. Never a user id. |
| `attributes` | no | Free-form bag, scrubbed. **An error's `message` and `stack` belong here** — there is no column for them, by design. |

Anything else is ignored. `userId` is not merely ignored, it is unstorable: there is no column.

**Failures are answered, not swallowed.** A batch that stores nothing returns
`{"stored":0,"dropped":N,"reasons":{…}}`, never a bare `202`. An unknown `/ingest/*` path returns a
404 naming the paths that exist. Both replies carry CORS headers for an allowlisted origin —
without them a browser cannot read the status at all and reports `TypeError: Failed to fetch`,
which is indistinguishable from this service being down. That indistinguishability is precisely why
the defect survived for months, so it is now covered by tests rather than by care.

Operators: `lantern_unknown_ingest_path_total` and `lantern_rum_dropped_total` are both "someone
believes they are reporting telemetry and are not". Neither should be nonzero for long.

## What it supersedes in `stack/infra/lantern`, and why

The frozen service is a genuinely thoughtful single-replica tool; the corrections here are the
things that do not survive contact with the estate it now lives in. Each was verified against source.

| Defect in the frozen service | Where | The correction here |
|---|---|---|
| **Ingest is open by default.** `NIMBUS_JWKS_URL` and `LANTERN_TOKEN` default to the empty string, and that pair makes `authMode()` return `'open'`, which serves every log line to anyone who can reach the port. | `stack/infra/lantern/src/env.js,43`, `src/auth.js,42` | `LANTERN_TOKEN` is **required**, length-checked, and refuses a placeholder (`src/env.ts`). |
| **No credential scrubbing at all.** `sanitise.js` strips NUL bytes and clamps numbers; "scrub" throughout the repo refers only to NUL-stripping. Every credential any service logged is stored in plain text for seven days. | `stack/infra/lantern/src/sanitise.js` (whole file) | Credentials removed **before persistence**, by kind, as a constant (`src/scrub.ts`, `src/ingest.ts`). |
| **The browser sink stores `user_id`.** | `stack/infra/lantern/src/server.js` (`userId: item.userId`) | No `user_id` column exists; `src/rum.ts` never reads the field; a test asserts it never reaches the database. |
| **The whole schedule is `setInterval`.** Two replicas flush and re-run DDL twice. | `stack/infra/lantern/src/index.js`, `store.js` | Every recurring task is a leased job keyed `global` (`src/jobs.ts`). |
| **DDL is re-run on every boot with no version table or advisory lock**, retried every 15s while Postgres is down. | `stack/infra/lantern/src/db.js`, `src/index.js,18-27` | Versioned migrations under an advisory lock, run by a one-shot `src/migrator.ts`; the service asserts the version and refuses to serve below it. |
| **Grouping explodes on the estate's own request ids** (16 chars of base32, not hex) and on 12-char container ids / git shas. | `stack/infra/lantern/src/fingerprint.js` | The correlation-id and 12-char-hash rules in `src/fingerprint.ts`. |
| **A resolved issue that recurs stays green** — the only state is a nullable `resolved_at`. | `stack/infra/lantern/src/db.js` | A `new → acknowledged → resolved → regressed` ladder; a later occurrence stamps `regressed_at`, enforced by `issues_regressed_has_time`. |
| **No `trace_id` on a log line**, so Lantern and Tempo are two unrelated records. | `stack/infra/lantern/src/db.js` | `trace_id`/`span_id` columns with a shape CHECK, and the request-id → trace lookup. |
| **The Docker socket is the primary collector** — a container with `/var/run/docker.sock` mounted has root on the host. | `stack/infra/lantern/src/env.js`, `src/docker.js` | OTLP push is primary; the socket collector is a dev-only fallback that boot **refuses** to enable outside `NODE_ENV=development` (`src/env.ts`). |

### One inherited claim found imprecise

`src/scrub.ts` states that a grep of the frozen repo for `redact`, `scrub`, `secret`, `bearer`
or `password` "finds the word only in comments about the service's own `LANTERN_TOKEN`." That is
not quite right: `scrub` appears in three NUL-stripping sites
(`stack/infra/lantern/src/sanitise.js`, `src/store.js`, `test/poison.test.js`) and `bearer`
is a live variable on the incoming-auth path (`src/auth.js,55,57`). The file's substantive claim —
that the frozen service has **no credential scrubbing** — holds exactly: every "scrub" in that repo
is about NUL bytes, not secrets. The behaviour is correct; only the parenthetical is loose, so it is
left in place and noted here rather than rewritten.

## Two modules, one process

Wave M1b folded `micro-analytics` into this repository. It is **not** a workspace package: the
absorbed code is plain directories under `src/analytics/`, imported by relative path, because
`org/.github/workflows/service-ci.yml` pins an allow-list of importable `@cloudsforge/*` names that
contains runtime packages only, and adding a SERVICE to it would defeat the rule it enforces.

| | what is shared | what is not |
|---|---|---|
| HTTP | one listener, one port, one `/livez`, `/readyz`, `/metrics` (lantern's) | two route tables, mounted in order; every analytics path is unchanged |
| Database | nothing | `LANTERN_DATABASE_URL` and `ANALYTICS_DATABASE_URL`, read unchanged, never merged |
| Readiness | one `Lifecycle` | two hard probes, `postgres-lantern` and `postgres-analytics` — `/readyz` is 503 if **either** database is gone |
| Metrics | one registry, one `/metrics` | every write goes through `metrics.withLabels({ module })`, so the two job planes are two series |
| Jobs | nothing | two queues, two runners, two `jobs` tables; both stop claiming together when the pod drains |
| Secrets | nothing | the pepper never leaves `src/analytics/` |

**The privacy boundary is made of scope, not convention.** `ANALYTICS_PSEUDONYM_KEY` and the
k-anonymity floor enter the process inside `src/analytics/module.ts` and are reachable from nothing
above it: that factory returns routes, a probe, a scrape hook and a lifetime, and none of those
names a secret. No lantern-side file imports past that seam, and `src/privacyboundary.test.ts`
fails if one ever does — including the migrator, which reaches analytics' DSNs through
`analyticsMigrationTargets()` rather than through its `env`.

**Both migrators run in the one `pnpm migrate`**, sequentially, each under its own advisory lock and
each writing its own database's `schema_migrations`. That table name is a literal inside
`@cloudsforge/db`, so the migrator **refuses to start** if the two DSNs address the same host, port
and database — see `src/migratortargets.ts`. It is not a theoretical guard: both modules declare a
migration named `events` and one named `jobs`, and both create tables of those names with different
columns.

**`ANALYTICS_TOKEN` now opens nothing.** It gated exactly one thing — analytics' `/metrics` — and
this process serves lantern's instead, because `x-lantern-token` is what Prometheus, the collector
and every runbook already present. The variable stays required, because the standalone analytics
service is deployed until cutover.

## What it talks to

- **Postgres** — two databases, `LANTERN_DATABASE_URL` and `ANALYTICS_DATABASE_URL`, and no others.
  Neither module reads the other's.
- **Identity** — JWKS verification for the operator read routes only; never dialled at boot, and
  its being down does not lock anyone out (that is what `LANTERN_TOKEN` is for).
- **The OTel collector** — pushes logs in; not called back.
- **Tempo** — not called; a trace id is turned into a link via `LANTERN_TRACE_URL_TEMPLATE`.

## Running it

```sh
pnpm install
pnpm typecheck
pnpm migrate        # one-shot, BOTH databases — never run by the service
pnpm start

# Tests. The database-backed suites run only against a *_test database, and this repository needs
# TWO — one per module. They must be different databases: both modules own a table called `events`
# and a table called `jobs`, so pointing them at one makes each suite truncate the other's rows.
#
#   both set    615 pass / 0 fail
#   neither     294 pass / 0 fail  (the no-database tier)
#   lantern only 367 pass / 0 fail — ten analytics suites SKIP, which CI treats as a failure
LANTERN_TEST_DATABASE_URL=postgres://lantern:lantern@127.0.0.1:5432/lantern_test \
ANALYTICS_TEST_DATABASE_URL=postgres://analytics:analytics@127.0.0.1:5432/analytics_test \
  pnpm test
```

Configuration is documented in `.env.example`; every value there is a `CHANGE_ME` placeholder, and
`src/env.ts` and `src/analytics/env.ts` each refuse to boot on one — so a merged pod refuses unless
BOTH halves are configured, rather than serving half a telemetry plane.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, under
human direction and review.
