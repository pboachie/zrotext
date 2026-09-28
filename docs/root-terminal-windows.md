# Candidate Windows console transport

`zrotext-root-terminal` is a dormant library for one bounded, no-echo ASCII
input operation. It has no CLI, recovery-codec dependency, root generation,
secret-reveal ceremony, enrollment, network, clipboard, keystore or file output.
It is not a usable owner recovery tool. `Session` is available only on Windows.

## Eligibility and ownership

Acquisition requires the current standard input, output and error handles to
be console character handles with the correct directions. It retains separate
non-inheritable duplicates, checks console modes, and rejects handle replacement.
The process must be in a nonzero, active Windows session whose WTS client
protocol is the local console protocol. Query failures are refusals.

These checks do not prove physical presence, an unrecorded terminal, or the
absence of a ConPTY/remoting host. The terminal host and other processes running
as the user remain trusted. Elevation policy and human consent belong to the
future CLI. There is no reopening of `CONIN$`/`CONOUT$`, allocation/attachment to
another console, blocking-input fallback, or redirected-stdio fallback.

A process-wide exclusive guard prevents overlapping adapter sessions. **The
caller must also ensure that no other attached process consumes input or changes
console modes.** Modes and the input queue are shared console resources; the
library cannot acquire exclusive ownership across unrelated processes.

Pre-existing queued events cause `Busy` without consuming the queue or changing
modes. After successful acquisition, this is a single-use session: cleanup
discards its queued tail events. This prevents pasted or overlong input from
being reused as the next prompt. It is not a guarantee about input typed after
the operation has returned to its caller.

## Input and restoration

The library saves the exact input mode and disables echo, line processing,
processed input, quick edit and VT input, then verifies the changed mode.
It dynamically resolves Microsoft's documented `ReadConsoleInputExW` export
from the pinned system Kernel32 module and uses `CONSOLE_READ_NOWAIT`. An absent
export is unsupported; waiting for input never substitutes a blocking read.

Limits are explicit: 1–128 printable ASCII bytes, at most five minutes for the
read loop, and at most 4,096 consumed input events. Backspace clears removed
bytes; Enter completes a nonempty line. Unicode, unsupported controls, overflow,
invalid repetition, changed handles/modes, and API errors fail closed. Escape,
Ctrl-C input and cooperative Ctrl-C/Ctrl-Break signals cancel. No entered
characters or masking stars are written to the screen.

The signal handler only sets an atomic cancellation flag. All normal, error,
timeout and cooperative-cancellation paths discard queued input owned by the
session, restore and verify the original mode, and unregister the handler before
returning a value. Cleanup failure discards the result and poisons the process's
adapter. Drop attempts cleanup during unwinding. Forced termination, console
close, logoff, shutdown and power loss cannot guarantee cleanup.

`SensitiveLine` holds a zeroizing fixed buffer and offers only an explicit byte
borrow; its Debug output is redacted. Input-record scratch storage is also
zeroizing. This does not promise erasure of OS queues, terminal-host storage,
register copies, screenshots or recordings. Public prompt output is limited to
512 printable ASCII/CR/LF bytes through `WriteConsoleW`, with short-write checks;
callers must never pass secret data to that public-prompt method.

## Native verification

`cargo test --locked -p zrotext-root-terminal` runs pure input tests on all
platforms. On Windows, named native tests launch their own hidden child console
with `CREATE_NEW_CONSOLE`, `SW_HIDE` and no inherited handles. Children verify
their isolated process list and hidden console window before injecting only
fixed synthetic events. Parent commands contain fixed case selectors, never
input bytes. Results are bounded exit codes; a watchdog terminates only its own
child. Redirection tests use child-local pipes, NUL or an owned zero-byte
temporary file deleted on close. No test attaches to the user's console.

The native tests check actual screen contents, no echo, exact mode restoration,
queued-input preservation, redirection of each standard handle, cancellation,
limits, changed handles/modes, API/cleanup faults, and poisoned-session behavior.
Hidden-console or session eligibility failures fail the tests; they are not
skipped. The existing read-only Windows workflow runs this suite. A Linux run
does not verify native console behavior. Human terminal/recovery ceremonies and
authenticated distribution remain separate future gates.

## API references

- [ReadConsoleInputExW](https://learn.microsoft.com/en-us/windows/console/readconsoleinputex)
- [GetConsoleMode](https://learn.microsoft.com/en-us/windows/console/getconsolemode)
- [SetConsoleMode](https://learn.microsoft.com/en-us/windows/console/setconsolemode)
- [SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)
- [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
- [WTS session information](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class)
