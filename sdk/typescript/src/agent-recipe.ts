// SPDX-License-Identifier: AGPL-3.0-only
/** Disabled recipe orchestration over the shared synthetic adapter.
 * This is not server-side authority, a reply service, or an activation path. */
import { agentReadiness, simulateSubmission, type SimulationResult } from './agent-adapter.js';
import { parseDraftEnvelope } from './draft01.js';

export const RECIPE_OPERATIONS = ['task_completion', 'owner_proposal', 'verified_reply'] as const;
export type RecipeOperation = typeof RECIPE_OPERATIONS[number];
export type RecipeScope = Readonly<{accountId: string; lineId: string; recipientId: string; readerId: string; expiresAt: number; maxTurns: number; budget: number}>;
export type RecipeEvent = Readonly<{eventId: string; actionId: string; accountId: string; lineId: string; recipientId: string; observedAt: number; expiresAt: number; digest: string; verified: boolean; kind: 'reply'|'stop'; contentAvailable: boolean; activeRequest: boolean}>;
export type RecipeCheckpoint = {
  synthetic: true; version: 1; accountId: string; lineId: string;
  revoked: boolean; takeover: boolean; stopped: boolean; turns: number; used: number;
  events: Record<string, {digest: string; actionId: string; result: string}>;
  notifications: Record<string, {digest: string; result: SimulationResult}>;
};
export type RecipeStore = {
  /** One durable atomic transaction must cover consumption and action identity. */
  transact<T>(run: (checkpoint: RecipeCheckpoint) => Promise<T>): Promise<T>;
};
export function newRecipeCheckpoint(scope: RecipeScope): RecipeCheckpoint {
  return {synthetic:true,version:1,accountId:scope.accountId,lineId:scope.lineId,revoked:false,takeover:false,stopped:false,turns:0,used:0,events:{},notifications:{}};
}
export type RecipeResult = Readonly<{synthetic: true; available: false; state: string; actionId?: string; content: 'unavailable'|'selected-reader'; modelProviderAccess: 'none'}>;
function result(state: string, actionId?: string, content: 'unavailable'|'selected-reader'='unavailable'): RecipeResult {
  return {synthetic:true,available:false,state,actionId,content,modelProviderAccess:'none'};
}
function identifier(value: unknown): value is string {
  return typeof value==='string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value) && !['constructor','prototype','__proto__'].includes(value);
}
export class AgentRecipe {
  private readonly scope: RecipeScope;
  constructor(scope: RecipeScope, private readonly store: RecipeStore, private readonly now: ()=>number) {
    this.scope=Object.freeze({...scope});
    if (![scope.accountId,scope.lineId,scope.recipientId,scope.readerId].every(value=>typeof value==='string'&&/^[a-z0-9_-]{1,64}$/.test(value)) || !Number.isSafeInteger(scope.expiresAt) || !Number.isSafeInteger(scope.maxTurns) || scope.maxTurns<1 || scope.maxTurns>3 || !Number.isSafeInteger(scope.budget) || scope.budget<1 || scope.budget>10) throw new Error('invalid_recipe_scope');
  }
  readiness() { return agentReadiness(); }
  private refuse(checkpoint: RecipeCheckpoint): string|undefined {
    if (checkpoint.synthetic!==true || checkpoint.version!==1 || checkpoint.accountId!==this.scope.accountId || checkpoint.lineId!==this.scope.lineId) return 'scope_mismatch';
    if (checkpoint.revoked) return 'revoked';
    if (checkpoint.takeover) return 'owner_takeover';
    if (checkpoint.stopped) return 'opted_out';
    if (this.now()>=this.scope.expiresAt) return 'expired';
    return undefined;
  }
  async taskCompletion(actionId: string, envelope: Uint8Array, unknown=false): Promise<RecipeResult> {
    if (!identifier(actionId)) return result('invalid_action');
    let snapshot: Uint8Array; let digest: string;
    try {
      if (!(envelope instanceof Uint8Array)) return result('invalid_envelope');
      snapshot=Uint8Array.from(envelope);
      const parsed=parseDraftEnvelope(snapshot);
      const hex=(bytes: Uint8Array)=>Array.from(bytes,byte=>byte.toString(16).padStart(2,'0')).join('');
      if (parsed.kind!==1 || hex(parsed.accountId)!==this.scope.accountId || hex(parsed.lineId)!==this.scope.lineId) return result('invalid_envelope');
      digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(parsed.unsigned).buffer)),byte=>byte.toString(16).padStart(2,'0')).join('');
    } catch { return result('invalid_envelope'); }
    return this.store.transact(async checkpoint=>{
      const refusal=this.refuse(checkpoint); if (refusal) return result(refusal);
      if (Object.hasOwn(checkpoint.notifications,actionId)) {
        const previous=checkpoint.notifications[actionId];
        return result(previous.digest===digest?previous.result.state:'action_identity_conflict',actionId);
      }
      if (checkpoint.used>=this.scope.budget || Object.keys(checkpoint.notifications).length>=32) return result('budget_exhausted');
      // This transaction has no external effects. Production integration would
      // need a durable pre-effect intent/outbox; this preview cannot provide it.
      checkpoint.notifications[actionId]={digest,result:{synthetic:true,state:'unknown',attempts:0,code:'submission_unknown'}};
      checkpoint.used++;
      const response=unknown ? ['disconnect' as const] : [{status:202,body:{message_id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',created:true}}];
      const outcome=await simulateSubmission(snapshot,response,1);
      checkpoint.notifications[actionId]={digest,result:outcome};
      return result(outcome.state,actionId);
    });
  }
  async ownerProposal(actionId: string): Promise<RecipeResult> {
    if (!identifier(actionId)) return result('invalid_action');
    return this.store.transact(async checkpoint=>result(this.refuse(checkpoint)??'awaiting_authenticated_exact_approval',actionId));
  }
  async verifiedReply(event: RecipeEvent): Promise<RecipeResult> {
    // Snapshot before the adapter awaits; received text cannot become a grant.
    event=Object.freeze({...event});
    if (event.verified!==true || !identifier(event.eventId) || !identifier(event.actionId) || !/^[a-f0-9]{64}$/.test(event.digest) || !Number.isSafeInteger(event.observedAt) || !Number.isSafeInteger(event.expiresAt) || event.observedAt<0 || event.expiresAt<=event.observedAt || !['reply','stop'].includes(event.kind) || typeof event.contentAvailable!=='boolean' || typeof event.activeRequest!=='boolean' || event.accountId!==this.scope.accountId || event.lineId!==this.scope.lineId || event.recipientId!==this.scope.recipientId) return result('unverified_or_foreign_event');
    return this.store.transact(async checkpoint=>{
      const refusal=this.refuse(checkpoint); if (refusal) return result(refusal);
      const previous=Object.hasOwn(checkpoint.events,event.eventId)?checkpoint.events[event.eventId]:undefined;
      if (previous) return result(previous.digest===event.digest&&previous.actionId===event.actionId?'replayed':'event_identity_conflict');
      if (this.now()>=event.expiresAt || event.observedAt>this.now() || (event.kind==='reply' && checkpoint.turns>=this.scope.maxTurns) || Object.keys(checkpoint.events).length>=128) return result('expired_or_turn_limit');
      let state:string;
      if (event.kind==='stop') { checkpoint.stopped=true; state='metadata_only_stop'; }
      else if (!event.activeRequest) state='owner_review';
      else if (!event.contentAvailable) state='content_unavailable';
      else { checkpoint.turns++; state='reply_routed_for_review'; }
      checkpoint.events[event.eventId]={digest:event.digest,actionId:event.actionId,result:state};
      // Consumption and proposed action identity are committed together by
      // the customer store. No reply, including "yes", approves an action.
      return result(state,event.actionId,event.kind==='reply'&&event.contentAvailable?'selected-reader':'unavailable');
    });
  }
}
