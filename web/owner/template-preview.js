// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const core = globalThis.ZtTemplatePreview;
  let epoch = 0, revision = 0, owner = null, ownerCookie = null;
  let active = true, signingOut = false, pending = null, timer = null;
  const say = (id, text) => { byId(id).textContent = text; };
  function cookie() {
    return document.cookie.split(";").map((part) => part.trim())
      .find((part) => part.startsWith("__Host-zrotext_csrf="))?.slice("__Host-zrotext_csrf=".length) || null;
  }
  function clearText() {
    revision++;
    byId("template").value = "";
    byId("substitutions").value = "";
    say("output", "");
    say("estimate", "");
    say("preview-status", "");
  }
  function conceal(hidden) {
    for (const id of ["editor", "output", "preview-status"]) byId(id).hidden = hidden;
  }
  function lock(message) {
    epoch++;
    pending?.abort();
    pending = null;
    owner = ownerCookie = null;
    clearText();
    conceal(false);
    byId("editor").disabled = true;
    byId("sign-out").disabled = true;
    say("session-status", message);
  }
  async function checkSession() {
    if (!active || signingOut) return false;
    const turn = ++epoch;
    pending?.abort();
    const controller = new AbortController();
    pending = controller;
    const timeout = setTimeout(() => controller.abort(), 15000);
    const proof = cookie();
    // Keep a verified, visible editor usable during routine revalidation.
    // Initial access and visibility resume remain locked until verification.
    if (!owner || ownerCookie !== proof || byId("editor").hidden) {
      byId("editor").disabled = true;
    }
    try {
      if (!proof) throw new Error("no session");
      const response = await fetch("/v1/auth/session", {
        credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
      });
      if (!response.ok) throw new Error("no session");
      const session = await response.json();
      if (turn !== epoch || !active) return false;
      if (proof !== cookie()) throw new Error("session changed");
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
      if (!session || ![session.account_id, session.user_id, session.session_id].every((id) => typeof id === "string" && uuid.test(id))) throw new Error("invalid session");
      const identity = [session.account_id, session.user_id, session.session_id].join(":");
      if (owner !== identity || ownerCookie !== proof) clearText();
      owner = identity;
      ownerCookie = proof;
      conceal(false);
      byId("editor").disabled = false;
      byId("sign-out").disabled = false;
      say("session-status", "Signed in. Preview text stays in this page.");
      return true;
    } catch {
      if (turn === epoch && active) lock("Sign-in could not be verified. Text cleared. Sign in, then check again.");
      return false;
    } finally {
      clearTimeout(timeout);
      if (pending === controller) pending = null;
    }
  }
  async function preview() {
    const identity = owner, proof = ownerCookie, edit = revision;
    say("output", "");
    say("preview-status", "");
    say("estimate", "");
    if (!identity || !await checkSession() || identity !== owner || proof !== ownerCookie || edit !== revision) return;
    try {
      const values = core.parseValues(byId("substitutions").value);
      const result = core.render(byId("template").value, values);
      say("output", result);
      const estimate = core.estimateSegments(result);
      say("estimate", `Estimate: ${estimate.parts} ${estimate.parts === 1 ? "part" : "parts"}, ${estimate.encoding === "gsm" ? `GSM, ${estimate.length} septets` : `UCS-2, ${estimate.length} code units`}. Estimate only.`);
      say("preview-status", "Preview ready. Nothing was sent or saved.");
    } catch (error) {
      say("preview-status", error.message);
    }
  }
  async function signOut() {
    if (signingOut) return;
    const proof = cookie();
    signingOut = true;
    lock("Text cleared. Signing out…");
    const turn = epoch;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      if (!proof) throw new Error("no session");
      const response = await fetch("/v1/auth/logout", {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: { "x-zrotext-csrf": proof }, signal: controller.signal,
      });
      if (!response.ok) throw new Error("logout failed");
      if (turn === epoch && active) say("session-status", "Signed out. Text cleared.");
    } catch {
      if (turn === epoch && active) say("session-status", "Text cleared, but sign-out could not be confirmed. Use Devices and sign in to manage your session.");
    } finally {
      clearTimeout(timeout);
      signingOut = false;
    }
  }
  function hide() {
    active = false;
    epoch++;
    pending?.abort();
    pending = null;
    clearInterval(timer);
    timer = null;
    byId("editor").disabled = true;
    byId("sign-out").disabled = true;
    conceal(true);
    say("session-status", "Preview hidden until sign-in is checked again.");
  }
  function suspend() {
    active = false;
    clearInterval(timer);
    timer = null;
    lock("Text cleared after leaving the page. Check sign-in to start again.");
  }
  function resume() {
    if (document.hidden) return;
    active = true;
    clearInterval(timer);
    timer = setInterval(checkSession, 15000);
    void checkSession();
  }
  byId("preview").addEventListener("click", preview);
  byId("clear").addEventListener("click", clearText);
  byId("check-session").addEventListener("click", checkSession);
  byId("sign-out").addEventListener("click", signOut);
  for (const id of ["template", "substitutions"]) byId(id).addEventListener("input", () => {
    revision++;
    say("output", "");
    say("preview-status", "");
    if (cookie() !== ownerCookie) lock("Sign-in changed. Text cleared. Check sign-in again.");
  });
  window.addEventListener("pagehide", suspend);
  window.addEventListener("beforeunload", suspend);
  window.addEventListener("pageshow", resume);
  document.addEventListener("visibilitychange", () => document.hidden ? hide() : resume());
  clearText();
  resume();
})();
