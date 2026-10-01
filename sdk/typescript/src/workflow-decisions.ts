// SPDX-License-Identifier: AGPL-3.0-only
/** Exact workflow-action-01 binding. Computing a digest grants no authority. */
export interface WorkflowActionDescriptor {
  account_id: string; action_id: string; revision: number;
  line_id: string; recipient_id: string; purpose_id: string;
  content_ref: string; content_digest: string; content_version: number;
  not_before: number; expires_at: number; timezone: string; window_id: string;
  routine_id: string; authority_generation: number;
  commitment: "informational" | "sensitive";
}
const names = ["account_id", "action_id", "authority_generation", "commitment",
  "content_digest", "content_ref", "content_version", "expires_at", "line_id",
  "not_before", "purpose_id", "recipient_id", "revision", "routine_id", "timezone",
  "window_id"] as const;
const integers = new Set<string>(["authority_generation", "content_version",
  "expires_at", "not_before", "revision"]);

export function canonicalWorkflowAction(value: unknown): Uint8Array<ArrayBuffer> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid action");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).sort().join("\0") !== names.join("\0")) throw new Error("invalid fields");
  const canonical: Record<string, unknown> = {};
  for (const name of names) {
    const item = input[name];
    if (integers.has(name)) {
      if (typeof item !== "number" || !Number.isSafeInteger(item)
        || item < (name === "not_before" ? 0 : 1)) throw new Error("invalid integer");
    } else if (typeof item !== "string" || item.length < 1 || item.length > 128
      || /[^\x00-\x7f]/u.test(item)) throw new Error("invalid identifier");
    canonical[name] = item;
  }
  if (!/^[0-9a-f]{64}$/u.test(input.content_digest as string)
    || !["informational", "sensitive"].includes(input.commitment as string)
    || (input.not_before as number) >= (input.expires_at as number)) throw new Error("invalid binding");
  // Match the normative Python ensure_ascii=True encoding, including ASCII DEL.
  return new TextEncoder().encode(JSON.stringify(canonical).replace(/\x7f/gu, "\\u007f"));
}

export async function workflowActionDigest(value: unknown): Promise<string> {
  // Snapshot every field before the first asynchronous operation.
  const canonical = canonicalWorkflowAction(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", canonical));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

export interface WorkflowActionKey {
  account_id: string; action_id: string; revision: number; binding_digest: string;
}
export type WorkflowActionPhase = "proposed" | "approved" | "invalidated" | "cancelled"
  | "expired" | "dispatching" | "unknown" | "succeeded" | "failed";
/** Historical metadata, never a reusable send capability. */
export interface WorkflowActionState {
  key: WorkflowActionKey; record_version: number; phase: WorkflowActionPhase;
}
