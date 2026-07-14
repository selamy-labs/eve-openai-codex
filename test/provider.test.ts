import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { generateText } from "ai";
import {
  CODEX_BASE_URL,
  codexRequestHeaders,
  createCodexProvider,
  decodeJwtClaims,
  selectCodexCredential,
  type CodexCredentialSource,
} from "../src/index.js";

function jwt(claims: object): string {
  const encode = (value: object | string) =>
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString(
      "base64url",
    );
  return `${encode({ alg: "none" })}.${encode(claims)}.${encode("signature")}`;
}

function completedResponse() {
  return {
    id: "resp_test",
    object: "response",
    created_at: 0,
    status: "completed",
    model: "gpt-5.5",
    output: [
      {
        id: "msg_test",
        type: "message",
        status: "completed",
        role: "assistant",
        content: [
          {
            type: "output_text",
            text: "ok",
            annotations: [],
            logprobs: [],
          },
        ],
      },
    ],
    usage: {
      input_tokens: 1,
      input_tokens_details: { cached_tokens: 0 },
      output_tokens: 1,
      output_tokens_details: { reasoning_tokens: 0 },
      total_tokens: 2,
    },
  };
}

test("decodes only well-formed JWT object claims", () => {
  assert.deepEqual(decodeJwtClaims("not-a-jwt"), {});
  assert.deepEqual(decodeJwtClaims("a..c"), {});
  assert.deepEqual(decodeJwtClaims("a.invalid-json.c"), {});

  const arrayPayload = Buffer.from(JSON.stringify(["not", "claims"])).toString(
    "base64url",
  );
  assert.deepEqual(decodeJwtClaims(`a.${arrayPayload}.c`), {});
  assert.deepEqual(decodeJwtClaims(jwt({ sub: "person" })), { sub: "person" });
});

test("selects access data but never returns a refresh token", () => {
  const selected = selectCodexCredential([
    {
      access_token: jwt({
        exp: 4_000_000_000,
        "https://api.openai.com/auth": { chatgpt_account_id: "account-123" },
      }),
      refresh_token: "must-not-cross-the-interface",
      label: "subscription",
    },
  ]);
  assert.equal(selected.accountId, "account-123");
  assert.equal(selected.label, "subscription");
  assert.equal("refreshToken" in selected, false);
});

test("selects a usable pool entry by priority and normalizes timestamps", () => {
  const now = 2_000_000_000;
  const selected = selectCodexCredential(
    {
      credential_pool: {
        "openai-codex": [
          { access_token: "", priority: 0 },
          {
            access_token: jwt({ exp: now + 10_000 }),
            last_error_reset_at: String(now + 500),
            priority: 1,
          },
          {
            access_token: jwt({ exp: now + 30 }),
            priority: 2,
          },
          {
            access_token: `  ${jwt({ exp: (now + 10_000) * 1000 })}  `,
            last_error_reset_at: "not-a-date",
            label: "   ",
            priority: 3,
          },
        ],
      },
    },
    { nowEpochSeconds: now, minTtlSeconds: 60 },
  );

  assert.equal(selected.label, "credential-4");
  assert.equal(selected.expiresAt, now + 10_000);
  assert.equal(selected.accessToken.startsWith("ey"), true);
  assert.match(selected.fingerprint ?? "", /^[a-f0-9]{12}$/);
});

test("accepts ISO claim expiry and skips an ISO reset window", () => {
  const now = Date.parse("2098-01-01T00:00:00Z") / 1000;
  const selected = selectCodexCredential(
    [
      {
        access_token: jwt({ exp: "2099-01-01T00:00:00Z" }),
        last_error_reset_at: "2098-02-01T00:00:00Z",
      },
      {
        access_token: jwt({ exp: "2099-01-01T00:00:00Z" }),
        last_error_reset_at: now - 1,
      },
    ],
    { nowEpochSeconds: now },
  );

  assert.equal(selected.label, "credential-2");
  assert.equal(selected.expiresAt, Date.parse("2099-01-01T00:00:00Z") / 1000);
});

test("rejects payloads without a usable access token", () => {
  const unavailable = [
    null,
    "not-a-pool",
    {},
    { credential_pool: null },
    { credential_pool: {} },
    { credential_pool: { "openai-codex": "not-an-array" } },
    [{ access_token: 42 }],
  ];

  for (const payload of unavailable) {
    assert.throws(
      () => selectCodexCredential(payload),
      /No non-expired OpenAI Codex access token is available/,
    );
  }
});

test("builds account-optional Codex headers with a custom user agent", () => {
  const headers = codexRequestHeaders(
    { accessToken: "token-without-account" },
    "codex_cli_rs/test",
  );
  assert.equal(headers.get("authorization"), "Bearer token-without-account");
  assert.equal(headers.get("chatgpt-account-id"), null);
  assert.equal(headers.get("originator"), "codex_cli_rs");
  assert.equal(headers.get("user-agent"), "codex_cli_rs/test");
});

test("supports an injected fetch and the default Codex base URL", async () => {
  let observedUrl = "";
  let observedHeaders = new Headers();
  const provider = createCodexProvider({
    credentialSource: {
      async getCredential() {
        return { accessToken: "injected-token" };
      },
    },
    userAgent: "codex_cli_rs/injected",
    async fetch(input, init) {
      observedUrl = String(input);
      observedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify(completedResponse()), {
        headers: { "content-type": "application/json" },
      });
    },
  });

  const result = await generateText({
    model: provider.responses("gpt-5.5"),
    prompt: "hello",
  });

  assert.equal(result.text, "ok");
  assert.equal(observedUrl, `${CODEX_BASE_URL}/responses`);
  assert.equal(observedHeaders.get("authorization"), "Bearer injected-token");
  assert.equal(observedHeaders.get("user-agent"), "codex_cli_rs/injected");
});

test("injects the Codex wire contract into a Responses request", async () => {
  let observed: {
    path: string;
    authorization: string;
    accountId: string;
    originator: string;
    userAgent: string;
    store: unknown;
  } = {
    path: "",
    authorization: "",
    accountId: "",
    originator: "",
    userAgent: "",
    store: undefined,
  };
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
        string,
        unknown
      >;
      observed = {
        path: request.url ?? "",
        authorization: request.headers.authorization ?? "",
        accountId: String(request.headers["chatgpt-account-id"] ?? ""),
        originator: String(request.headers.originator ?? ""),
        userAgent: request.headers["user-agent"] ?? "",
        store: body.store,
      };
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(completedResponse()));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address() as AddressInfo;
    const credentialSource: CodexCredentialSource = {
      async getCredential() {
        return { accessToken: "oauth-token", accountId: "account-123" };
      },
    };
    const provider = createCodexProvider({
      credentialSource,
      baseURL: `http://127.0.0.1:${address.port}`,
    });
    const result = await generateText({
      model: provider.responses("gpt-5.5"),
      prompt: "hello",
      providerOptions: { openai: { store: false } },
    });

    assert.equal(result.text, "ok");
    assert.deepEqual(observed, {
      path: "/responses",
      authorization: "Bearer oauth-token",
      accountId: "account-123",
      originator: "codex_cli_rs",
      userAgent: "codex_cli_rs/0.0.0 (Eve OpenAI Codex)",
      store: false,
    });
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
