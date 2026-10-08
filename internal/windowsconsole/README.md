# Hidden Windows invitation input

`ReadInvitation(context.Context, func() error)` accepts one canonical
43-character unpadded base64url invitation through the local Windows console.
The returned bytes are still encoded, not decoded key material. The caller must
clear them after use. Every failure matches `ErrInput` through `errors.Is`, with
the same fixed error text. `CategoryOf` and `Diagnostic` expose only a closed
failed-operation category, without native or callback diagnostics, console mode
values, records or partial input. Unknown errors map to `unknown`; error text is
never inspected. Other platforms fail with the `unsupported` category.

Categories distinguish fixed-API resolution, `CONIN$` open/type, initial mode
read/set/verification, pre-prompt discard, prompt, record read, input decoding,
context cancellation and cleanup. The first cleanup failure takes precedence
(discard, restore set/verification, close); otherwise the original failure is
retained. Cleanup cancellation after valid input fails closed as `context`.
Categorization never adds native reads, probes, retries or console operations.

## Boundary

- Opens the fixed `CONIN$` device using `CreateFileW`; never reads standard input,
  caller-specified files, arguments, environment variables or command output.
- Requires both `FILE_TYPE_CHAR` and successful `GetConsoleMode`.
- Uses a noninheritable handle and only a fixed System32 `kernel32.dll` export.
  It does not spawn commands, attach/create a console or fall back to a file.
- Disables echo, line processing, processed input, virtual-terminal input and
  Quick Edit, and verifies the mode before displaying the public prompt.
- Clears pre-prompt type-ahead. Reads one native `INPUT_RECORD` at a time using
  documented `ReadConsoleInputExW(CONSOLE_READ_NOWAIT)`. A missing export fails
  closed before any console-mode change.
- Checks cancellation between every record, including mouse/window/focus
  records, and during each at-most-25-millisecond no-input wait. It does not use
  `ReadConsole`, a readiness-check followed by a blocking read, a worker thread
  abandoned on timeout, or unbounded waits.
- Accepts ASCII base64url characters, bounded key repeats, backspace and Enter.
  Invalid input, overlength input, Ctrl+C, Escape and Ctrl+Z fail closed. Strict
  base64 decoding validates the final unused bits before returning a copy.
- On every normal/error return and during callback panic unwinding, clears local
  buffers, flushes unread input before restoring echo, restores and verifies the
  original mode, and closes the handle. Any cleanup failure clears the result
  and fails the operation. The original Quick Edit mode is restored using the
  required extended-flags sequence.
- Serializes calls within this process with context-aware acquisition. Other
  processes already attached to the same console are outside this boundary;
  this is not protection against a compromised host or another console reader.

The public prompt callback must return promptly and must not read input or print
secrets. Native configuration/open/cleanup calls have no Windows timeout; the
bounded cancellation guarantee covers waiting for console input. Terminating
the process or console abruptly can prevent deferred restoration. This package
does not create credentials or grant enrollment authority.

## Verification

The tests use in-memory console fixtures only, including cleanup failures,
callback errors/panics, original modes without extended flags, cancellation
without keyboard input, and cancellation at successful input completion. The
portable record-layout test checks the 20-byte, four-byte-aligned Windows ABI.
Open-sequence fixtures cover API resolution, open, type rejection and handle
cleanup, including exact ordering. Closed-category tests check every category,
unknown values and wrappers whose error text must never be evaluated. The
Windows-specific test compares constants only and invokes no native API.

Cross-compilation establishes compilation, not live console acceptance. No test
here enters credentials, changes a real console, provisions a key, installs a
service or changes host permissions. A separately authorized, human-operated
Windows console check is still required before claiming native acceptance.

## Microsoft references

- [Console handles](https://learn.microsoft.com/en-us/windows/console/console-handles)
- [GetConsoleMode](https://learn.microsoft.com/en-us/windows/console/getconsolemode)
- [SetConsoleMode](https://learn.microsoft.com/en-us/windows/console/setconsolemode)
- [ReadConsoleInputEx](https://learn.microsoft.com/en-us/windows/console/readconsoleinputex)
- [INPUT_RECORD](https://learn.microsoft.com/en-us/windows/console/input-record-str)
- [KEY_EVENT_RECORD](https://learn.microsoft.com/en-us/windows/console/key-event-record-str)
- [FlushConsoleInputBuffer](https://learn.microsoft.com/en-us/windows/console/flushconsoleinputbuffer)
