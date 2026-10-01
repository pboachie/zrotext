/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
(() => {
  const ownerLinks = [...document.querySelectorAll("[data-owner-only]")];
  const observerLink = document.getElementById("owner-observer-link");
  const status = document.getElementById("owner-nav-status");
  const billing = document.getElementById("owner-billing-link");
  let generation = 0;
  function clear() {
    generation++;
    for (const link of ownerLinks) link.hidden = true;
    if (observerLink) observerLink.hidden = true;
    if (status) status.textContent = "Sign in to open owner controls. Real sending remains gated.";
  }
  async function refresh() {
    clear();
    const epoch = generation;
    try {
      const response = await fetch("/v1/auth/session", { credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(30000) });
      if (!response.ok) return;
      const session = await response.json();
      if (epoch !== generation) return;
      if (session.role === "observer") {
        if (observerLink) observerLink.hidden = false;
        if (status) status.textContent = "Observer access: use the read-only device-status view.";
        return;
      }
      if (session.role !== "owner") return;
      for (const link of ownerLinks) if (link !== billing) link.hidden = false;
      if (status) status.textContent = "Owner controls. Connected status does not prove carrier readiness.";
      if (!billing) return;
      try {
        const view = await fetch("/v1/billing/status", { credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(30000) });
        if (!view.ok) return;
        const body = await view.json();
        if (epoch === generation && body.mode === "test") billing.hidden = false;
      } catch { /* Disabled or unavailable billing must not advertise a working destination. */ }
    } catch { /* Existing page controllers report sign-in errors; navigation stays closed. */ }
  }
  document.addEventListener("zrotext-owner-session", event => {
    if (event.detail && event.detail.signedIn) refresh();
    else clear();
  });
  refresh();
})();
