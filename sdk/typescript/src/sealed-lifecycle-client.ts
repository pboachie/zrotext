// SPDX-License-Identifier: AGPL-3.0-only
/** Default-off sealed queue metadata. A cancellation timeout has an unknown
 * result: callers query status; this client never retries or resubmits work. */
export const SEALED_MESSAGE_STATES = ["accepted", "queued", "claimed", "submitting", "submitted", "delivered", "delivery_unknown", "unknown", "failed", "cancelled", "expired"] as const;
export type SealedMessageState = typeof SEALED_MESSAGE_STATES[number];
export type SealedMessageMetadata = Readonly<{
  message_id: string; device_id: string; state: SealedMessageState; state_version: number;
  created_at_ms: number; updated_at_ms: number; expires_at_ms: number;
}>;
export type SealedMessagePage = Readonly<{ messages: readonly SealedMessageMetadata[]; next_cursor: string | null }>;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function identity(id: string): string {
  if (!UUID.test(id)) throw new Error("Sealed lifecycle identity must be a lowercase UUID");
  return id;
}
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Invalid sealed lifecycle response");
  return value as Record<string, unknown>;
}
function metadata(value: unknown): SealedMessageMetadata {
  const row = object(value);
  const keys = ["message_id", "device_id", "state", "state_version", "created_at_ms", "updated_at_ms", "expires_at_ms"];
  if (Object.keys(row).length !== keys.length || keys.some(key => !(key in row))) throw new Error("Invalid sealed lifecycle metadata");
  for (const key of ["message_id", "device_id"]) if (typeof row[key] !== "string" || !UUID.test(row[key] as string)) throw new Error("Invalid sealed lifecycle identity");
  if (!SEALED_MESSAGE_STATES.includes(row.state as SealedMessageState)) throw new Error("Invalid sealed lifecycle state");
  for (const key of ["state_version", "created_at_ms", "updated_at_ms", "expires_at_ms"]) if (!Number.isSafeInteger(row[key]) || (row[key] as number) < (key === "state_version" ? 1 : 0)) throw new Error("Invalid sealed lifecycle timestamp/version");
  return row as SealedMessageMetadata;
}
async function boundedJson(response: Response): Promise<unknown> {
  if (!response.body) throw new Error("Missing sealed lifecycle response");
  const reader=response.body.getReader(); const chunks:Uint8Array[]=[]; let length=0;
  try {
    for (;;) {
      const part=await reader.read(); if (part.done) break;
      length+=part.value.byteLength;
      if (length>16384) { await reader.cancel(); throw new Error("Oversized sealed lifecycle response"); }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const bytes=new Uint8Array(length); let offset=0;
  for (const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
}
export class SealedLifecycleError extends Error {
  constructor(readonly status: number, readonly code: string) { super(`Sealed lifecycle request failed: ${code}`); }
}
export class SealedLifecycleClient {
  private readonly origin: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;
  private readonly transport: typeof fetch;
  constructor(options: Readonly<{baseUrl: string; apiToken: string; timeoutMs?: number; fetchImpl?: typeof fetch}>) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username || url.password) throw new Error("Sealed lifecycle requires an HTTPS origin");
    if (typeof options.apiToken !== "string" || !/^[\x21-\x7e]+$/.test(options.apiToken)) throw new Error("Invalid sealed lifecycle credential");
    this.origin=url.origin; this.apiToken=options.apiToken; this.timeoutMs=options.timeoutMs ?? 15000; this.transport=options.fetchImpl ?? fetch;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs <= 0) throw new Error("Invalid sealed lifecycle timeout");
  }
  async status(messageId: string): Promise<SealedMessageMetadata> {
    const result=metadata(await this.request("GET",`/v1/sealed/messages/${identity(messageId)}`));
    if (result.message_id !== messageId) throw new Error("Sealed lifecycle response identity mismatch");
    return result;
  }
  async cancel(messageId: string): Promise<SealedMessageMetadata> {
    const result=metadata(await this.request("POST",`/v1/sealed/messages/${identity(messageId)}/cancel`));
    if (result.message_id !== messageId || result.state !== "cancelled") throw new Error("Invalid sealed cancellation evidence");
    return result;
  }
  async list(cursor?: string): Promise<SealedMessagePage> {
    const row=object(await this.request("GET",`/v1/sealed/messages${cursor === undefined ? "" : `?cursor=${identity(cursor)}`}`));
    if (Object.keys(row).length !== 2 || !Array.isArray(row.messages) || row.messages.length > 20 || !(row.next_cursor === null || typeof row.next_cursor === "string" && UUID.test(row.next_cursor))) throw new Error("Invalid sealed lifecycle page");
    const messages=row.messages.map(metadata);
    if (row.next_cursor !== null && (messages.length !== 20 || row.next_cursor !== messages.at(-1)?.message_id)) throw new Error("Invalid sealed lifecycle cursor");
    return {messages,next_cursor:row.next_cursor as string|null};
  }
  private async request(method: "GET"|"POST", path: string): Promise<unknown> {
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),this.timeoutMs);
    try {
      const response=await this.transport(`${this.origin}${path}`,{method,headers:{authorization:`Bearer ${this.apiToken}`,accept:"application/json"},signal:controller.signal,redirect:"error"});
      const row:unknown=await boundedJson(response);
      if (response.status!==200) {
        const error=object(row);
        const codes:Record<string,number>={invalid_request:400,unauthorized:401,forbidden:403,not_found:404,cancellation_conflict:409,rate_limited:429,unavailable:503};
        if (Object.keys(error).length!==1 || typeof error.code!=="string" || codes[error.code]!==response.status) throw new Error("Invalid sealed lifecycle error response");
        throw new SealedLifecycleError(response.status,error.code);
      }
      return row;
    } finally { clearTimeout(timer); }
  }
}
