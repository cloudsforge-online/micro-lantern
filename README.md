# lantern

The estate's **error-tracking plane**: it takes the log lines every service emits, removes the
credentials they carry, groups the occurrences into *issues*, and answers the one question an
operator actually asks — "here is a request id off an error screen; what happened, and where is the
trace?"

It is a leaf. Nothing in the estate calls it, and it calls nothing at boot. Beacon failing is not a
service failure, and neither is this one.

## What it is

- **`POST /otlp/v1/logs`** — the primary ingest path. The OTel collector's `otlphttp/lantern`
  exporter posts OTLP **protobuf** here (`../deploy/otel/collector.yaml:198`,
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
- **`/livez`, `/readyz`, and an authenticated `/metrics`.** Scraping this plane costs a credential,
  because `/metrics` publishes which services are failing and how fast.
- **Leased background work** (`src/jobs.ts`): hourly retention sweep, five-minute rollups, and
  auto-resolve of stale issues — each claimed `FOR UPDATE SKIP LOCKED`, so two replicas do the work
  once. No `setInterval`.

## What it supersedes in `stack/infra/lantern`, and why

The frozen service is a genuinely thoughtful single-replica tool; the corrections here are the
things that do not survive contact with the estate it now lives in. Each was verified against source.

| Defect in the frozen service | Where | The correction here |
|---|---|---|
| **Ingest is open by default.** `NIMBUS_JWKS_URL` and `LANTERN_TOKEN` default to the empty string, and that pair makes `authMode()` return `'open'`, which serves every log line to anyone who can reach the port. | `stack/infra/lantern/src/env.js:35,43`, `src/auth.js:24-31,42` | `LANTERN_TOKEN` is **required**, length-checked, and refuses a placeholder (`src/env.ts`). |
| **No credential scrubbing at all.** `sanitise.js` strips NUL bytes and clamps numbers; "scrub" throughout the repo refers only to NUL-stripping. Every credential any service logged is stored in plain text for seven days. | `stack/infra/lantern/src/sanitise.js` (whole file) | Credentials removed **before persistence**, by kind, as a constant (`src/scrub.ts`, `src/ingest.ts`). |
| **The browser sink stores `user_id`.** | `stack/infra/lantern/src/server.js:136` (`userId: item.userId`) | No `user_id` column exists; `src/rum.ts` never reads the field; a test asserts it never reaches the database. |
| **The whole schedule is `setInterval`.** Two replicas flush and re-run DDL twice. | `stack/infra/lantern/src/index.js:18-27`, `store.js` | Every recurring task is a leased job keyed `global` (`src/jobs.ts`). |
| **DDL is re-run on every boot with no version table or advisory lock**, retried every 15s while Postgres is down. | `stack/infra/lantern/src/db.js:52-172`, `src/index.js:13,18-27` | Versioned migrations under an advisory lock, run by a one-shot `src/migrator.ts`; the service asserts the version and refuses to serve below it. |
| **Grouping explodes on the estate's own request ids** (16 chars of base32, not hex) and on 12-char container ids / git shas. | `stack/infra/lantern/src/fingerprint.js:14-30` | The correlation-id and 12-char-hash rules in `src/fingerprint.ts`. |
| **A resolved issue that recurs stays green** — the only state is a nullable `resolved_at`. | `stack/infra/lantern/src/db.js:96` | A `new → acknowledged → resolved → regressed` ladder; a later occurrence stamps `regressed_at`, enforced by `issues_regressed_has_time`. |
| **No `trace_id` on a log line**, so Lantern and Tempo are two unrelated records. | `stack/infra/lantern/src/db.js:60-78` | `trace_id`/`span_id` columns with a shape CHECK, and the request-id → trace lookup. |
| **The Docker socket is the primary collector** — a container with `/var/run/docker.sock` mounted has root on the host. | `stack/infra/lantern/src/env.js:16`, `src/docker.js:12` | OTLP push is primary; the socket collector is a dev-only fallback that boot **refuses** to enable outside `NODE_ENV=development` (`src/env.ts`). |

### One inherited claim found imprecise

`src/scrub.ts:9-11` states that a grep of the frozen repo for `redact`, `scrub`, `secret`, `bearer`
or `password` "finds the word only in comments about the service's own `LANTERN_TOKEN`." That is
not quite right: `scrub` appears in three NUL-stripping sites
(`stack/infra/lantern/src/sanitise.js:65`, `src/store.js:53`, `test/poison.test.js:64`) and `bearer`
is a live variable on the incoming-auth path (`src/auth.js:46,55,57`). The file's substantive claim —
that the frozen service has **no credential scrubbing** — holds exactly: every "scrub" in that repo
is about NUL bytes, not secrets. The behaviour is correct; only the parenthetical is loose, so it is
left in place and noted here rather than rewritten.

## What it talks to

- **Postgres** — its own database (`LANTERN_DATABASE_URL`), and no other.
- **Identity** — JWKS verification for the operator read routes only; never dialled at boot, and
  its being down does not lock anyone out (that is what `LANTERN_TOKEN` is for).
- **The OTel collector** — pushes logs in; not called back.
- **Tempo** — not called; a trace id is turned into a link via `LANTERN_TRACE_URL_TEMPLATE`.

## Running it

```sh
pnpm install
pnpm typecheck
pnpm migrate        # one-shot, against LANTERN_DATABASE_URL — never run by the service
pnpm start

# tests (the database-backed suite runs only against a *_test database)
LANTERN_TEST_DATABASE_URL=postgres://lantern:lantern@127.0.0.1:5432/lantern_test pnpm test
```

Configuration is documented in `.env.example`; every value there is a `CHANGE_ME` placeholder, and
`src/env.ts` refuses to boot on one.
