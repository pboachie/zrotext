// Executable comparison examples. These functions do not create clients or credentials.
// Supply a client configured for the same independently chosen account/device scope.
export const readLegacyStatus = (client, messageId) => client.getStatus(messageId);
export const readGeneratedStatus = (client, messageId) => client.public.alphaMessages.getStatus({ messageId });

export function generatedSubmissionArgs(intent) {
  return {
    client_message_id: intent.clientMessageId, device_id: intent.deviceId,
    recipient_e164: intent.recipientE164, test_case_id: intent.testCaseId,
    expires_at_ms: intent.expiresAtMs,
  };
}

// Persist intent and idempotencyKey before invoking either submission path.
export const submitLegacy = (client, intent, idempotencyKey) => client.submit(intent, idempotencyKey);
export const previewGenerated = (client, intent, idempotencyKey) =>
  client.public.alphaMessages.submit.preview(generatedSubmissionArgs(intent), { idempotencyKey });

// The caller must review the preview independently before passing its token.
// A local runtime token is not server owner approval or radio permission.
export const submitGeneratedReviewed = (client, intent, idempotencyKey, confirmationToken) =>
  client.public.alphaMessages.submit(generatedSubmissionArgs(intent), { idempotencyKey, confirm: confirmationToken });

export function needsReconciliation(state) {
  return state === 'unknown' || state === 'delivery_unknown';
}
