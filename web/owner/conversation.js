// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const el = (id) => document.getElementById(id);
  let adapter = globalThis.ZtConversationSimulatorAdapter;
  const ordinary = !globalThis.ZtConversationOwnerSetup && globalThis.ZtConversationOwnerSetupFactory;
  const setup = globalThis.ZtConversationOwnerSetup || (ordinary && ordinary.create({enabled:true,host:el("custody-artifacts"),readSelection:()=>({enabled:el("owner-enabled").checked,contentConsent:el("content-consent").checked,integrationReadersText:el("integration-readers").value,integrationTransferConsent:el("integration-transfer-consent").checked,sessionConsent:el("session-custody").checked,account_id:el("owner-account").value,device_id:el("owner-device").value,line_id:el("owner-line").value,binding_generation:Number(el("owner-generation").value),peer:el("owner-peer").value,rootFingerprint:el("owner-fingerprint").value,manifestVersion:el("owner-version").value,manifestDigest:el("owner-digest").value,event_id:el("owner-event").value,genesisConsent:el("genesis-consent").checked,phoneSigningFingerprint:el("genesis-phone-signing-fingerprint").value,phoneFingerprint:el("genesis-phone-fingerprint").value,archiveKeyId:el("genesis-archive-id").value})}));
  if (!adapter && !setup) return; // No implicit credentials, network or activation.
  let controller = adapter ? ZtConversation.create(adapter) : null;
  let setupPending = false, setupRevision = 0;
  let custodyLifetime = null, rootEnrollment = null, rootLifetime = null, lineSetup = null, lineLifetime = null;
  let factsSource = null, facts = null, factsPending = null, factsUsed = false, factsPreparing = false;
  const factsIdentity = () => ({ context: el("facts-context").value, expires: el("facts-expires").value });
  const retainFactsPending = () => { const state = facts?.state(); if (state?.phase === "saved") factsPending = null; else if (state?.pending) factsPending = Object.freeze({ ...state.pending }); return state; };
  function renderFacts() {
    const state = retainFactsPending();
    el("facts-open").disabled = !ordinary || !factsSource || !controller?.state().scope || setupPending || factsUsed;
    el("facts-context").disabled = factsUsed; el("facts-expires").disabled = factsUsed;
    if (factsPending) {
      el("facts-status").textContent = `Save outcome unknown. Context ${factsPending.contextId}, request ${factsPending.requestId}, revision ${factsPending.revision}, digest ${factsPending.envelopeDigest}. After closing, only this status remains; do not create a replacement context.`;
      el("connect").disabled = true;
    } else if (state?.phase === "saved") el("facts-status").textContent = "Encrypted facts saved. Currentness was checked when saved.";
    else if (state?.phase === "closed" || state?.phase === "refused") el("facts-status").textContent = "Facts editor closed. No new initial facts identity is created in this page.";
  }
  let hadScope = false;
  function render() {
    renderFacts();
    lineSetup?.state(); // Local identity/expiry guard only; no background HTTP.
    const s = controller ? controller.state() : { scope: null, draft: "", review: null, canConfirm: false, busy: setupPending, messages: [] };
    if (s.scope) hadScope = true;
    else if (hadScope && adapter && !globalThis.ZtConversationSimulatorAdapter) adapter.close();
    if(s.uncertain) el("status").textContent = `Send outcome unknown. Check delivery before sending again. Message ID: ${s.uncertain.messageId}`;
    el("composer").disabled = !s.scope || s.busy;
    el("confirm").disabled = !s.canConfirm;
    el("confirmation").hidden = !s.review;
    el("review-body").textContent = s.review?.body || "";
    el("review-peer").textContent = s.review ? `Account ${s.review.scope.account} · Line ${s.review.scope.line} · To ${s.review.scope.peer}` : "";
    el("selection").textContent = s.scope ? `Account ${s.scope.account} · Line ${s.scope.line} · Peer ${s.scope.peer}` : "";
    el("body").value = s.draft;
    el("messages").replaceChildren();
    for (const message of s.messages) {
      const p = document.createElement("p"); p.textContent = `${message.direction === "inbound" ? "Phone received" : message.status === "queued" ? "Queued for delivery" : "Simulator accepted"}: ${message.body}`;
      el("messages").append(p);
    }
  }
  async function action(fn) {
    try { await fn(); } catch { const uncertain=controller?.state().uncertain; el("status").textContent = uncertain ? `Send outcome unknown. Check delivery before sending again. Message ID: ${uncertain.messageId}` : "Action unavailable. Check authorization and review again; no automatic retry occurs."; }
    render();
  }
  el("connect").disabled = false;
  el("connect").addEventListener("click", () => action(async () => {
    if (controller?.state().uncertain) throw Error("Check delivery before sending again");
    retainFactsPending(); if (factsPending) throw Error("Original facts outcome remains unknown");
    if (setupPending) throw Error("Setup in progress");
    setupPending = true; el("connect").disabled = true;
    el("status").textContent = "Checking conversation authorization.";
    let ticket = ++setupRevision;
    let selectedFactsSource = null;
    try {
    if (setup && !globalThis.ZtConversationSimulatorAdapter) {
      if (!el("session-custody").checked) throw Error("Explicit session custody decision required");
      adapter?.close(); controller?.clear(); controller = null;
      hadScope = false; ticket = ++setupRevision;
      render();
      custodyLifetime?.abort(); custodyLifetime = new AbortController();
      const sdk = await import("/v1/owner/conversation-sdk/sdk/conversation-custody.js");
      const options = await setup.custodyOptions({signal:custodyLifetime.signal});
      const custody = await sdk.prepareConversationCustody02({ ...options, signal: custodyLifetime.signal });
      if (ticket !== setupRevision) { custody.close(); throw Error("Setup closed"); }
      try { adapter = ZtConversationOwnerTransport.create({ ...setup.transportOptions, enabled: true, custody }); }
      catch (error) { custody.close(); throw error; }
      controller = ZtConversation.create(adapter);
      selectedFactsSource = { options, custody, signal: custodyLifetime.signal };
      adapter.onClose?.(clear);
      setup.onClose?.(clear);
    }
    await controller.authorize(); el("status").textContent = setup ? "Conversation authorized for this session." : "Fixture conversation authorized.";
    if (adapter.initialEvent) await controller.read(adapter.initialEvent);
    if (ticket !== setupRevision || custodyLifetime?.signal.aborted) throw Error("Setup closed");
    factsSource = selectedFactsSource;
    } finally { setupPending = false; el("connect").disabled = Boolean(factsPending); }
  }));
  el("body").addEventListener("input", () => { try { controller.edit(el("body").value); } catch { controller.clear(); } render(); });
  el("review").addEventListener("click", () => action(async () => {
    await controller.prepare(); render();
    if (controller.state().canConfirm) el("review-body").focus();
  }));
  el("confirm").addEventListener("click", () => action(async () => {
    const result = await controller.confirm(); el("status").textContent = result.status === "queued" ? "Confirmed message queued. Delivery is pending." : "Simulator accepted the confirmed message. Carrier delivery is not tested.";
  }));
  el("cancel").addEventListener("click", () => { try { controller.edit(controller.state().draft); } catch { controller.clear(); } render(); el("body").focus(); });
  const clear = () => {
    setupRevision++;
    let failure;
    retainFactsPending(); factsSource = null;
    for(const close of [()=>facts?.close(),()=>lineLifetime?.abort(),()=>lineSetup?.close(),()=>rootLifetime?.abort(),()=>rootEnrollment?.close(),()=>custodyLifetime?.abort(),()=>{if(ordinary)setup.close();},()=>adapter?.close?.()])try{close();}catch(error){failure??=error;}
    retainFactsPending();
    lineSetup=null;rootEnrollment=null;
    try {
      for(const id of ["root-mfa","line-mfa","root-backup-file","root-card-file","root-signatures-file","line-phone-point-file","line-root-signature-file","activation-file","genesis-phone-file","genesis-archive-file"])try{el(id).value="";}catch(error){failure??=error;}
    } finally {try{controller?.clear();}finally{hadScope=false;el("status").textContent="Conversation cleared. Check authorization again.";render();}}
    if(failure)throw failure;
  };
  // Initial facts use the actual post-enrollment setup/custody, never the simulator.
  el("facts-open").addEventListener("click", async () => {
    const actionRevision = setupRevision;
    try {
    if (!ordinary || !factsSource || factsUsed || factsPreparing || setupPending || !controller?.state().scope) throw Error("Facts setup unavailable");
    const selected = factsIdentity(), source = factsSource, ticket = setupRevision;
    if (selected.context.length !== 36 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(selected.context) || selected.context === "00000000-0000-0000-0000-000000000000" || !/^[1-9][0-9]{0,18}$/.test(selected.expires) || /[^0-9]/.test(selected.expires)) throw Error("Explicit context and expiry required");
    const expiresMs = BigInt(selected.expires); if (expiresMs >= (1n << 63n)) throw Error("Facts expiry unavailable");
    const contextId = Uint8Array.from(selected.context.replaceAll("-", "").match(/../g), value => parseInt(value, 16));
    const binding = { ...source.options.binding };
    for (const name of ["account", "device", "line", "interval", "session", "phoneReader", "archiveReader"]) binding[name] = Uint8Array.from(binding[name]);
    factsUsed = true; factsPreparing = true; renderFacts();
    const live = () => { if (ticket !== setupRevision || source !== factsSource || source.signal.aborted || document.hidden || selected.context !== el("facts-context").value || selected.expires !== el("facts-expires").value) throw Error("Facts setup closed"); };
    let candidate;
    try {
      live(); await source.options.readCurrent(); live();
      const sdk = await import("/v1/owner/conversation-sdk/sdk/owner-context-authoring.js"); live();
      candidate = sdk.createOwnerContextAuthoring({ enabled: true, origin: window.location.origin, host: el("facts-editor"), binding, contextId, expiresMs,
        readCurrent: () => source.options.readCurrent(), currentCsrf: () => setup.transportOptions.currentCsrf(), archiveLease: source.options.archiveLease,
        onSetupClose: listener => setup.onClose(listener), onCustodyClose: listener => source.custody.onClose(listener), signal: source.signal });
      live(); facts = candidate; el("facts-status").textContent = "Review local facts before saving. Availability requires the configured owner context service; a refusal is not a save.";
    } catch (error) { candidate?.close(); throw error; }
    finally { factsPreparing = false; renderFacts(); }
    } catch { if (actionRevision === setupRevision && !document.hidden) el("facts-status").textContent = "Facts unavailable. Check authorization and the independently selected context and expiry; no automatic retry occurs."; }
    render();
  });
  for (const id of ["facts-context", "facts-expires"]) el(id).addEventListener("input", () => { if (factsUsed || factsPreparing) clear(); });
  if (ordinary && globalThis.ZtConversationLineSetup) {
    const lineSelection=()=>({enabled:el("owner-enabled").checked,sessionConsent:el("line-session-consent").checked,account_id:el("owner-account").value,device_id:el("owner-device").value,line_id:el("owner-line").value,nextGeneration:el("owner-generation").value,rootFingerprint:el("owner-fingerprint").value,pairedFingerprint:el("line-paired-fingerprint").value,origin:el("root-origin").value});
    const lineButtons=phase=>{for(const [id,phases]of [["line-complete",["awaiting_root"]],["line-reconcile",["registration_unknown"]],["line-open",["registered"]],["line-check",["awaiting_device","awaiting_owner","activation_committed","activation_unknown"]],["line-approve",["awaiting_owner"]]])el(id).disabled=!phases.includes(phase);};
    lineButtons("unprepared");el("line-begin").disabled=false;
    const lineResult=value=>{lineButtons(value.phase);el("line-status").textContent=value.phase==="phone_acknowledged"?"SEALED line installation acknowledged by the paired phone. Initial manifest setup and content consent remain separate.":value.phase==="activation_committed"?"Activation committed. Phone installation acknowledgment is still required.":value.phase==="awaiting_owner"?`Paired phone declares Android API ${value.androidApi}, one active SIM, local subscription ${value.subscription}. Compare the selected SIM on the phone before separate approval.`:`Line setup phase: ${value.phase}. No automatic retry occurs.`;};
    const lineAction=fn=>action(async()=>{if(setupPending)throw Error("Setup in progress");setupPending=true;const ticket=setupRevision;let candidate=lineSetup,candidateLifetime=lineLifetime;try{const pending=fn();candidate=lineSetup;candidateLifetime=lineLifetime;const value=await pending;if(ticket!==setupRevision){candidateLifetime?.abort();candidate?.close();throw Error("Line setup closed");}lineResult(value);}catch(error){if(ticket!==setupRevision){candidateLifetime?.abort();candidate?.close();}if(lineSetup){const state=lineSetup.state();lineButtons(state.phase);if(state.phase.endsWith("unknown"))el("line-status").textContent="Line setup outcome unknown. Use the explicit check button; do not repeat approval or MFA.";}throw error;}finally{setupPending=false;el("line-mfa").value="";}});
    el("line-begin").addEventListener("click",()=>lineAction(async()=>{if(el("line-phone-point-file").files.length!==1)throw Error("Existing paired public point required");lineLifetime?.abort();lineSetup?.close();lineLifetime=new AbortController();lineSetup=ZtConversationLineSetup.create({enabled:true,host:el("line-artifacts"),readSelection:lineSelection});lineSetup.onClose(()=>{for(const id of ["line-mfa","line-phone-point-file","line-root-signature-file"])try{el(id).value="";}catch{}try{lineButtons("closed");}catch{}el("line-status").textContent="Session line approval key closed. Fresh offline root approval is required for an unactivated replacement.";});return await lineSetup.begin(el("line-phone-point-file").files[0],{signal:lineLifetime.signal});}));
    el("line-complete").addEventListener("click",()=>lineAction(async()=>{if(!lineSetup||el("line-root-signature-file").files.length!==1)throw Error("Existing line root approval required");const factor=el("line-mfa").value;el("line-mfa").value="";return await lineSetup.complete(el("line-root-signature-file").files[0],factor);}));
    for(const [id,method]of [["line-reconcile","reconcileRegistration"],["line-open","open"],["line-check","view"],["line-approve","approve"]])el(id).addEventListener("click",()=>lineAction(async()=>{if(!lineSetup)throw Error("Explicit session line setup required");return await lineSetup[method]();}));
    el("sealed-line-setup").addEventListener("input",event=>{if(["line-mfa","line-root-signature-file"].includes(event.target.id))return;if(lineSetup)clear();});
  }
  if (ordinary && globalThis.ZtConversationRootEnrollment) {
    const rootIdentity = () => ({enabled:el("owner-enabled").checked,publicationConsent:el("root-publication-consent").checked,account_id:el("owner-account").value,backup_id:el("root-backup-id").value,rootFingerprint:el("owner-fingerprint").value,origin:el("root-origin").value});
    el("root-begin").addEventListener("click",()=>action(async()=>{
      if(setupPending)throw Error("Setup in progress");
      setupPending=true; const ticket=++setupRevision;
      try {
        rootLifetime?.abort(); rootEnrollment?.close(); rootLifetime=new AbortController();
        if(el("root-backup-file").files.length!==1||el("root-card-file").files.length!==1)throw Error("Existing root artifacts required");
        rootEnrollment=ZtConversationRootEnrollment.create({enabled:true,host:el("root-artifacts"),readIdentity:rootIdentity});
        await rootEnrollment.begin(el("root-backup-file").files[0],el("root-card-file").files[0],{signal:rootLifetime.signal});
        if(ticket!==setupRevision)throw Error("Root setup closed");
        el("status").textContent="Public root challenge prepared. Existing offline custody approval is required; no root enrollment or content consent has occurred.";
      } catch(error) {rootLifetime?.abort();rootEnrollment?.close();throw error;} finally {setupPending=false;el("root-mfa").value="";}
    }));
    el("root-complete").addEventListener("click",()=>action(async()=>{
      if(setupPending||!rootEnrollment||el("root-signatures-file").files.length!==1)throw Error("Existing root challenge and public signatures required");
      setupPending=true; const ticket=setupRevision, factor=el("root-mfa").value; el("root-mfa").value="";
      try {await rootEnrollment.complete(el("root-signatures-file").files[0],factor);if(ticket!==setupRevision)throw Error("Root setup closed");el("root-signatures-file").value="";el("status").textContent="Existing root custody enrolled and independently reread for this owner session. Initial manifest setup, conversation activation and content consent remain separate.";}
      finally {setupPending=false;el("root-mfa").value="";}
    }));
    el("root-enrollment").addEventListener("input",event=>{if(["root-mfa","root-signatures-file"].includes(event.target.id))return;if(rootEnrollment)clear();});
  }
  if (ordinary) {
    el("provision-initial").addEventListener("click",()=>action(async()=>{if(el("genesis-phone-file").files.length!==1||el("genesis-archive-file").files.length!==1)throw Error("Existing public phone and archive files required");const ticket=++setupRevision;custodyLifetime?.abort();custodyLifetime=new AbortController();const checkpoint=await setup.provisionInitial(el("genesis-phone-file").files[0],el("genesis-archive-file").files[0],{signal:custodyLifetime.signal});if(ticket!==setupRevision)throw Error("Genesis closed");el("owner-version").value=checkpoint.manifestVersion;el("owner-digest").value=checkpoint.manifestDigest;el("genesis-phone-file").value="";el("genesis-archive-file").value="";el("status").textContent="Initial public manifest installed and independently verified. Record the accepted checkpoint shown above. Separate activation and explicit phone approval remain required.";}));
    el("prepare-activation").addEventListener("click",()=>action(async()=>{const ticket=++setupRevision;custodyLifetime?.abort();custodyLifetime=new AbortController();await setup.activate(undefined,{signal:custodyLifetime.signal});if(ticket!==setupRevision)throw Error("Activation closed");el("status").textContent="Activation submitted. Download the public phone setup candidate below; explicit phone approval and installation are still required before checking authorization.";}));
    el("activate-conversation").addEventListener("click",()=>action(async()=>{if(el("activation-file").files.length!==1)throw Error("Existing root-signed activation successor required");const ticket=++setupRevision;custodyLifetime?.abort();custodyLifetime=new AbortController();await setup.activate(el("activation-file").files[0],{signal:custodyLifetime.signal});if(ticket!==setupRevision)throw Error("Activation closed");el("activation-file").value="";el("status").textContent="Activation submitted. Download the public phone setup candidate below; explicit phone approval and installation are still required before checking authorization.";}));
    el("owner-setup").addEventListener("input",event=>{if(event.target.closest("#custody-artifacts")||event.target.id==="activation-file"||event.target.closest("#root-enrollment")||event.target.closest("#sealed-line-setup"))return;if(custodyLifetime||setupPending||rootEnrollment||lineSetup){clear();}});
    el("session-custody").addEventListener("change",()=>{if(custodyLifetime||setupPending){clear();}});
  }
  el("clear").addEventListener("click", clear);
  window.addEventListener("pagehide", clear);
  document.addEventListener("visibilitychange", () => { if (document.hidden) clear(); });
  adapter?.onClose?.(clear);
  setInterval(render, 1000);
  render();
})();
