# ADR-0001: Separate provider protocol from credential custody

## Status

Accepted

## Date

2026-07-14

## Context

Eve accepts any Vercel AI SDK `LanguageModel`, so a Codex integration does not
need to modify Eve's execution runtime. Authentication custody varies widely:
local CLIs, Kubernetes fleets, brokers, and desktop apps should not share one
storage implementation.

## Decision

Expose a small async `CodexCredentialSource` interface and build the AI SDK
provider around it. Resolve that source for every model request. When an access
token is near expiry or a replayable request receives `401`, signal the source
to refresh and, for `401`, identify the rejected access token before retrying
once. The source may reread externally rotated state or perform its own
serialized refresh transaction.

Keep OAuth login, refresh-token exchange, storage, rotation, and deployment
outside this package. Parse legacy credential-pool JSON only through an optional
pure helper that returns access-token data and discards refresh data.

## Consequences

- Eve agents compose the provider directly with `defineAgent`.
- Credential rotation can be centralized without changing the provider.
- A host can recover from stale projected access tokens without giving the
  provider refresh-token custody.
- The package can be proposed upstream without Selamy-specific dependencies.
- Consumers remain responsible for establishing a safe refresh-token writer.
