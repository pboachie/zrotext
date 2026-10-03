// SPDX-License-Identifier: AGPL-3.0-only
import { ReplyEventAdapter } from './reply-events.mjs';
import { createOriginalReplyReceiver } from './original-reply-events.mjs';
/** Trusted-local composition. Never translates event identities or classifies original text. */
export async function createCustomerReplies({ metadata, original }) {
  if (!(metadata instanceof ReplyEventAdapter)) throw new Error('invalid_configuration');
  const receiver = await createOriginalReplyReceiver(original);
  return Object.freeze({
    ingestMetadataStop(raw, headers) {
      // This shape restriction grants no authority: the existing adapter still authenticates exact bytes.
      let event; try { event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { throw new Error('invalid_event'); }
      if (event.type !== 'inbound.message' || !['opt_out', 'opt_out_review'].includes(event.classification) || event.content_kind !== 'metadata_only') throw new Error('invalid_event');
      return metadata.ingest(raw, headers);
    },
    ingestOriginal: (raw, headers) => receiver.ingest(raw, headers),
    pageOriginal: (cursor = null, limit = 20) => receiver.page(cursor, limit),
    processOriginal: (eventId, activeRequestId, propose) => receiver.process(eventId, activeRequestId, propose, () => metadata.assertAutomaticCurrent()),
    consumeOwnerReview: eventId => receiver.consume({ event_id: eventId, active_request_id: null, descriptor: null }),
    exportOriginal: options => receiver.exportMetadata(options),
    retainOriginal: () => receiver.retain(),
    eraseOriginal: () => receiver.erase(),
    close: () => receiver.close(),
  });
}
