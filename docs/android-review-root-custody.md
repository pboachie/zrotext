# Android isolated review root custody

The Setup screen has a separate **Open isolated review workspace custody** entry. It opens the configured HTTPS review origin at `/review/root` inside the app. The corresponding review backend must be explicitly configured and mounted; this Android entry does not enable it or create a workspace. The ordinary owner ceremony, MFA, permissions, and device signing authority remain separate.

The review browser signs in and establishes its typed workspace session. Native custody then obtains current metadata through the same WebView cookies and the observational `/v1/review/session/context` endpoint. It checks the echoed request, current owner and broker identities, effective deadlines, configuration digest and monotonic revision. Cookie, password and private locator values never enter JNI. The native typed review context cannot substitute for an ordinary owner session.

Before the first root ceremony, save the private workspace selector using the native pane. It first authenticates the narrow selector and its association through `/v1/review/locator/context`. The Android document picker writes a separate private file and reads back the exact bytes. Only then does the app sync an immutable acknowledgement request to private storage and send the confirmation. Interrupted confirmation uses the original request through status; it never creates another acknowledgement automatically. A positive acknowledgement can delete only the matching selector cookie. The file identifies private workspace context; it is not a login credential or root proof. Configuration or authentication-key rotation can make it unavailable. Keep it separate from public root files.

For a workspace with no root history or pending enrollment:

1. Check review sign-in, create the real native root kit, reveal its recovery token once and confirm that it was recorded separately.
2. Save the encrypted backup, public card and public receipt with the Android document picker. Reopen the independently retained backup and card, enter the account and full fingerprint from the saved receipt, and perform fresh native recovery.
3. Return to the same review browser. Supply the public root pin, fingerprint, encrypted backup and public card to its first-root form. Issue one proposal and copy its public Base64 challenge into native custody.
4. Review the account, origin, full root fingerprint, backup UUID, backup/card digests, custody-statement digest, challenge and original deadline. Explicit consent plus fresh recovery produces exactly one enrollment signature and one custody signature. Copy the public two-line response back to the browser and complete its password-confirmed ceremony there.
5. Recover the retained kit again as necessary, then verify the actual server receipt and signed encrypted-custody export against that kit. The historical receipt actor is not treated as current session authority.

A pending enrollment requires the original kit and exact original challenge. Enrolled, historical and unavailable states refuse replacement creation. Root generation, approval, recovery and publication do not enroll a phone, grant SMS authority, enable dispatch or establish full messaging access.

The browser pauses its own single-flight HTTP chains before native handoff or controlled file picking. Its acknowledgement is coordination only; it does not prove that a request had no effect. The same WebView document is retained while native custody is visible. Unrelated backgrounding or navigation retires that rendering context; controlled file-picker background has a finite lifetime. Lifecycle changes clear secret input and burn pending native approvals. A failed or interrupted operation requires reconciliation of the original result.

The native service owns challenge and kit copies, checks the actual current context before secret recovery and after dropping recovered root material, and consumes its one-shot handle before recovery. Public JNI allocation failure also closes the operation. Managed buffers, WebView cookies, OS providers and input-method copies cannot promise complete zeroization.

Focused tests cover native recovery and real dual signatures, one-shot cancellation and time bounds, strict context/cookie parsing, configuration changes, public custody verification, browser pause coordination, private readback and durable acknowledgement reconciliation, and the ordinary app entry. Source tests and native ABI/export checks do not qualify a signed release, a physical phone, a live mounted review backend, or carrier delivery.
