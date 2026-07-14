import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { generateText } from "ai";
import {
  createCodexProvider,
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
      response.end(
        JSON.stringify({
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
        }),
      );
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
