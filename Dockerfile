# syntax=docker/dockerfile:1.7
#
# Build context is this repository, plus one named context for the unpublished runtime packages:
#
#   docker build -t lantern --build-context runtimepkgs=../runtime .
#
# The extra context is temporary. Once the @cloudsforge/* packages are published (AD-02),
# package.json takes registry versions, the COPY lines marked below are deleted, the flag goes
# away, and this becomes an ordinary single-context build.
#
# It is named `runtimepkgs` rather than `runtime` because a build context and a build stage share
# one namespace, and the final stage below is called `runtime`.

# ----------------------------------------------------------------------------------- deps
FROM node:22-slim AS deps
# Pin pnpm in the image. The runtime workspace is installed before this service's own package.json
# is copied, so corepack has no packageManager field to read at that point and would otherwise grab
# whatever is latest and then refuse to switch to the 11.9.0 the runtime pins.
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate
WORKDIR /app

# Temporary: the link: dependencies resolve to ../runtime relative to this directory, so the
# packages must exist at that path inside the image for the lockfile to stay frozen. `link:` in
# particular resolves at install time to the sibling's own node_modules.
COPY --from=runtimepkgs package.json pnpm-workspace.yaml pnpm-lock.yaml /runtime/
COPY --from=runtimepkgs packages /runtime/packages

# Install the runtime workspace's OWN dependencies first. `link:` uses the sibling as-is and does
# not manage its dependency tree, so `/runtime`'s node_modules must exist independently — both for
# `tsc` to resolve the runtime source it typechecks (jose, @opentelemetry/api) and for
# `node --import tsx` to load @cloudsforge/* at run time. Without this the image builds a set of
# @cloudsforge symlinks that point at source which cannot resolve its own imports.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store,sharing=locked \
    pnpm --dir /runtime install --frozen-lockfile --config.store-dir=/pnpm-store

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# `--frozen-lockfile` is the point of the step: a build that silently resolves a different
# dependency tree from the one CI tested is a build whose provenance means nothing.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store,sharing=locked \
    pnpm install --frozen-lockfile --config.store-dir=/pnpm-store

# ----------------------------------------------------------------------------------- build
# `tsc --noEmit` rather than an emit: tsx runs the TypeScript sources directly, exactly as every
# service in the estate already does. What this stage buys is that a type error fails the image
# build instead of the first request.
FROM deps AS build
COPY tsconfig.json tsconfig.base.json ./
COPY src ./src
RUN pnpm typecheck

# ----------------------------------------------------------------------------------- runtime
FROM node:22-slim AS runtime
WORKDIR /app

# No corepack, no pnpm, no build toolchain in the final image: fewer things an RCE can reach, and
# nothing at runtime needs them.
# `/runtime` comes across too: /app/node_modules holds @cloudsforge/* as symlinks into it, so
# without the target the links dangle and the first `import '@cloudsforge/db'` fails at run time.
COPY --from=build /runtime /runtime
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/tsconfig.json /app/tsconfig.base.json ./
COPY --from=build /app/src ./src

# node:22-slim ships an unprivileged `node` user (uid 1000). Nothing is written to the filesystem
# at runtime, so read-only ownership of the image is sufficient.
USER node

# No secret is baked in, and none may be: every value in src/env.ts is supplied by the deploy at
# run time. There is no ENV line here on purpose — least of all LANTERN_TOKEN, which is what gates
# /metrics and is therefore exactly the thing a leaked image layer would hand over.
ENV NODE_ENV=production
EXPOSE 4010

# The health endpoints are for the orchestrator, not for the image: the balancer probes /readyz and
# the restart policy probes /livez. A HEALTHCHECK here would duplicate that in a second place that
# then drifts.

# The migrator is a SEPARATE one-shot process — `node --import tsx src/migrator.ts` — run as an
# init container or a Kubernetes Job before this ever starts. It is deliberately not invoked here:
# below SCHEMA_VERSION the `issues_resolved_has_time`/`issues_regressed_has_time` CHECKs and the
# trace-id shape guards may not exist, and a service that could create them at boot is a service
# that could start without them. `index.ts` asserts the schema version and refuses to serve below it.
CMD ["node", "--import", "tsx", "src/index.ts"]
