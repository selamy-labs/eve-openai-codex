# Eve OpenAI Codex

`@selamy-labs/eve-openai-codex` is a composable ChatGPT Codex OAuth provider
for Eve and the Vercel AI SDK. It accepts a caller-owned credential source and
returns a normal AI SDK OpenAI provider configured for the Codex Responses
endpoint.

The package is intentionally independent of Kubernetes, secret managers,
filesystems, and OAuth login flows. Applications retain credential custody and
decide whether tokens come from a file, broker, workload identity service, or
another source.

```ts
import { createCodexProvider } from "@selamy-labs/eve-openai-codex";

const codex = createCodexProvider({
  credentialSource: {
    async getCredential() {
      return { accessToken: await broker.getAccessToken() };
    },
  },
});

const model = codex.responses("gpt-5.5");
```

For Eve, pass `model` directly to `defineAgent`. Set the OpenAI provider option
`store: false` for the subscription-backed Codex endpoint.

## Public contract

- `CodexCredentialSource` supplies one access credential per request.
- `createCodexProvider` injects bearer, originator, user-agent, and optional
  ChatGPT account headers into an AI SDK provider. Its Responses transport also
  normalizes Eve/AI SDK requests to the stricter Codex wire contract.
- `normalizeCodexRequestBody` forces ephemeral storage, moves system/developer
  input into top-level instructions, preserves encrypted reasoning continuity,
  and removes response fields that the subscription endpoint rejects.
- `selectCodexCredential` parses either a credential array or a Hermes-shaped
  `credential_pool.openai-codex` document and returns access data only.
- No API accepts, returns, exchanges, or persists a refresh token.

## Verification

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm coverage
pnpm build
bazel test //...
```

The suite enforces at least 90% line, branch, function, and statement coverage.
It covers credential parsing and expiry behavior, then uses a fake server to
verify the `/responses` route, all required headers, and the non-storage request
option. A consumer must still run a live test with an authorized ChatGPT Codex
account to prove subscription compatibility.

## Upstream path

The integration is packaged separately so its API and tests can mature without
coupling Eve to one organization's credential custody. An upstream Eve change
could adopt this implementation, expose it as an official integration, or use
the tests as the provider contract. Consumers should depend on the public
interfaces rather than internal functions so that transition remains small.
