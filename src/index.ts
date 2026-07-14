import { createHash } from "node:crypto";
import { createOpenAI } from "@ai-sdk/openai";

export const CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex";

export interface CodexAccessCredential {
  accessToken: string;
  accountId?: string;
  expiresAt?: number;
  fingerprint?: string;
  label?: string;
}

export interface CodexCredentialRequest {
  refresh: boolean;
  rejectedAccessToken?: string;
}

export interface CodexCredentialSource {
  getCredential(request?: CodexCredentialRequest): Promise<CodexAccessCredential>;
}

export interface CreateCodexProviderOptions {
  credentialSource: CodexCredentialSource;
  baseURL?: string;
  fetch?: typeof globalThis.fetch;
  userAgent?: string;
}

export interface SelectCodexCredentialOptions {
  minTtlSeconds?: number;
  nowEpochSeconds?: number;
}

type JsonRecord = Record<string, unknown>;

const CREDENTIAL_REFRESH_SKEW_SECONDS = 60;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function messageText(content: unknown): string | undefined {
  if (typeof content === "string" && content.trim()) return content.trim();
  if (!Array.isArray(content)) return undefined;

  const parts = content
    .filter(isRecord)
    .filter((part) => part.type === "input_text" || part.type === "text")
    .map((part) => part.text)
    .filter((text): text is string => typeof text === "string" && Boolean(text.trim()))
    .map((text) => text.trim());
  return parts.length > 0 ? parts.join("\n") : undefined;
}

export function normalizeCodexRequestBody(
  body: BodyInit | null | undefined,
): BodyInit | null | undefined {
  if (typeof body !== "string") return body;

  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    return body;
  }
  if (!isRecord(payload)) return body;

  payload.store = false;
  delete payload.max_output_tokens;
  delete payload.temperature;

  if (Array.isArray(payload.input)) {
    const instructions: string[] = [];
    const input = payload.input.filter((item) => {
      if (!isRecord(item) || (item.role !== "system" && item.role !== "developer")) {
        return true;
      }
      const text = messageText(item.content);
      if (!text) return true;
      instructions.push(text);
      return false;
    });
    if (typeof payload.instructions === "string" && payload.instructions.trim()) {
      instructions.unshift(payload.instructions.trim());
    }
    if (instructions.length > 0) payload.instructions = instructions.join("\n\n");
    payload.input = input;
  }

  payload.include = ["reasoning.encrypted_content"];
  if (Array.isArray(payload.tools) && payload.tools.length > 0) {
    payload.tool_choice ??= "auto";
    payload.parallel_tool_calls ??= true;
  } else {
    delete payload.tool_choice;
    delete payload.parallel_tool_calls;
  }

  return JSON.stringify(payload);
}

function isResponsesRequest(input: string | URL | Request): boolean {
  const url = input instanceof Request ? input.url : String(input);
  return new URL(url).pathname.endsWith("/responses");
}

function isReplayableRequest(
  input: string | URL | Request,
  body: BodyInit | null | undefined,
): boolean {
  return !(input instanceof Request) && (body == null || typeof body === "string");
}

function expiresWithinRefreshSkew(credential: CodexAccessCredential): boolean {
  return (
    credential.expiresAt !== undefined &&
    credential.expiresAt <= Date.now() / 1000 + CREDENTIAL_REFRESH_SKEW_SECONDS
  );
}

export function decodeJwtClaims(token: string): JsonRecord {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return {};
  try {
    const payload: unknown = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    return isRecord(payload) ? payload : {};
  } catch {
    return {};
  }
}

function parseEpoch(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1_000_000_000_000 ? value / 1000 : value;
  }
  if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return parseEpoch(numeric);
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed / 1000;
  }
  return undefined;
}

function extractPoolEntries(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;
  if (!isRecord(payload)) return [];
  const pool = payload.credential_pool;
  if (!isRecord(pool)) return [];
  const entries = pool["openai-codex"];
  return Array.isArray(entries) ? entries : [];
}

export function selectCodexCredential(
  payload: unknown,
  options: SelectCodexCredentialOptions = {},
): CodexAccessCredential {
  const now = options.nowEpochSeconds ?? Date.now() / 1000;
  const minTtl = options.minTtlSeconds ?? 60;
  const entries = extractPoolEntries(payload)
    .filter(isRecord)
    .map((entry, index) => ({ entry, index }))
    .sort((left, right) => {
      const leftPriority =
        typeof left.entry.priority === "number" ? left.entry.priority : left.index;
      const rightPriority =
        typeof right.entry.priority === "number"
          ? right.entry.priority
          : right.index;
      return leftPriority - rightPriority;
    });

  for (const { entry, index } of entries) {
    const token = entry.access_token;
    if (typeof token !== "string" || !token.trim()) continue;
    const resetAt = parseEpoch(entry.last_error_reset_at);
    if (resetAt !== undefined && resetAt > now) continue;

    const claims = decodeJwtClaims(token);
    const expiresAt = parseEpoch(claims.exp);
    if (expiresAt !== undefined && expiresAt <= now + minTtl) continue;

    const auth = claims["https://api.openai.com/auth"];
    const accountId = isRecord(auth) ? auth.chatgpt_account_id : undefined;
    const label =
      typeof entry.label === "string" && entry.label.trim()
        ? entry.label.trim()
        : `credential-${index + 1}`;

    return {
      accessToken: token.trim(),
      ...(typeof accountId === "string" && accountId ? { accountId } : {}),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      fingerprint: createHash("sha256").update(token).digest("hex").slice(0, 12),
      label,
    };
  }

  throw new Error("No non-expired OpenAI Codex access token is available");
}

export function codexRequestHeaders(
  credential: CodexAccessCredential,
  userAgent = "codex_cli_rs/0.0.0 (Eve OpenAI Codex)",
): Headers {
  const headers = new Headers({
    Authorization: `Bearer ${credential.accessToken}`,
    "User-Agent": userAgent,
    originator: "codex_cli_rs",
  });
  if (credential.accountId) {
    headers.set("ChatGPT-Account-ID", credential.accountId);
  }
  return headers;
}

export function createCodexProvider(options: CreateCodexProviderOptions) {
  const request = options.fetch ?? globalThis.fetch;
  return createOpenAI({
    baseURL: options.baseURL ?? CODEX_BASE_URL,
    apiKey: "oauth-access-token-is-injected-by-fetch",
    fetch: async (input, init) => {
      const body = isResponsesRequest(input)
        ? normalizeCodexRequestBody(init?.body)
        : init?.body;
      const send = (credential: CodexAccessCredential) => {
        const headers = new Headers(init?.headers);
        codexRequestHeaders(credential, options.userAgent).forEach((value, key) => {
          headers.set(key, value);
        });
        if (body !== init?.body) headers.delete("content-length");
        return request(
          input,
          body === undefined ? { ...init, headers } : { ...init, body, headers },
        );
      };

      let credential = await options.credentialSource.getCredential({
        refresh: false,
      });
      if (expiresWithinRefreshSkew(credential)) {
        credential = await options.credentialSource.getCredential({ refresh: true });
      }

      const response = await send(credential);
      if (response.status !== 401 || !isReplayableRequest(input, body)) {
        return response;
      }

      const refreshedCredential = await options.credentialSource.getCredential({
        refresh: true,
        rejectedAccessToken: credential.accessToken,
      });
      return send(refreshedCredential);
    },
  });
}
