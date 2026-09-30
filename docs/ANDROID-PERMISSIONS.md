# Android permission controls

The gateway requests permissions after a purpose-specific disclosure and an affirmative **Agree and continue** action. **Not now**, dismissing the dialog, and opening the app do not request permissions.

- **Choose SIM permissions** requests phone-state access to enumerate active SIMs and, on Android 13 or later, notification access for the foreground connection status and Pause action. It does not request SMS access.
- **Review SMS sending access** requests only SMS sending access. The controlled one-shot test still requires manual arming and an authenticated server grant; permission approval does not initiate a send.
- **Review SMS receiving access** requests only SMS receiving access. Newly received SMS can be processed in the background. Local suppression records and encrypted sender information support STOP/review handling. Approved reply windows can store encrypted bodies locally. The authenticated inbound pilot uploads signed metadata rather than reply bodies. Opt-out synchronization can upload the sender number and withdrawal metadata.

**Manage or revoke permissions** opens Android app settings. Pause stops a connection; it does not revoke receiving access or erase existing records. Revoke SMS access in Android settings to stop further local SMS processing. Pairing and connection tests do not require SMS permission.

These controls do not establish Google Play permission eligibility. The current app exposes connection and controlled SMS pilots; it does not claim that a complete cross-device SMS conversation product is available. Restricted permissions require a truthful declaration for the exact shipped functionality and Google review.
