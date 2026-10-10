# Selected Windows event message content: source candidate

`internal/windowseventcontent` adds a separate, explicit local source for actual
Windows event **message text**. It is a source-only foundation, not a released
installer, persistent grant, manager API, endpoint transport or dashboard. The
existing `internal/windowsevents` header-only package and its callers remain
unchanged. A manager upgrade or successful metadata read grants no content scope.

## Caller contract

`Read(context.Context, Request) (Report, error)` accepts `Request.Events`, an
ordered slice of 1–16 existing `windowsevents.Event` identities. Every selection
must include all six header fields: exact channel, nonzero record ID, 16-bit
event ID, level, provider name and UTC timestamp at native 100-nanosecond
precision. Only the exact `Application` and `System` channel names are accepted.
Duplicate channel/record pairs, arbitrary channel names, paths, queries, remote
targets and missing identities are rejected before native calls.

Each record is queried by its numeric `EventRecordID`, and the six metadata
properties are reread and matched before message formatting. This guards against
ordinary log clearing/replacement and stale selected rows; it is not a
cryptographic event identity or an immutable snapshot. No latest-event fallback
is allowed. A disappeared record reports a fixed `record_not_found` reason; a
reused record ID with different metadata cannot release content.

`Report.Events` preserves the exact requested order. Each `Result` includes the
selected `Event`, `Message`, `Quality`, `Complete`, `Truncated` and optional fixed
`Reason`. The report adds a fixed `Source`, UTC `CollectedAt`, `Warning` and
aggregate quality/completeness/truncation. Completeness means every selected
message was successfully formatted without truncation. It says nothing about
other log records or retention history. An empty successfully formatted message
is a complete result; a missing message is an explicit unavailable result.

`ValidateRequest(Request)` and `ValidateReport(Report, Request)` are portable,
nonmutating validation helpers for a separately implemented grant/transport
boundary. They check selection bounds, identity/order, fixed provenance/warning,
UTF-8 limits, reason taxonomy and consistent per-row/aggregate states. They do
not authorize collection, storage, transport, AI use or export.

## Privacy boundary

Every valid report carries this warning:

> Event messages may contain credentials, personal data and other secrets.
> Authorized operator-only content; do not send to AI providers or export.

Messages are original formatted text, with optional explicitly marked byte
truncation. They are **not sanitized or secret-free**. Formatting can interpolate
event insertion values, including names, paths, identities and credentials.
The package does not return raw XML, `EventData`, `UserData`, a System security
subtree, `Computer`, a separate SID field or the `Security` channel. This does
not imply that formatted text cannot itself contain any of those values.

There is no default collection, subscription, bookmark, custom query, file-log
input, remote session, shell/PowerShell/wevtutil invocation, privilege change or
write API. No native read occurs during package initialization or ordinary tests.
The package uses only the caller's existing local permissions. It neither
persists content nor sends it anywhere. Integrations must obtain a separate
explicit local content grant, preserve its exact selected identity and original
expiry, and keep content restricted to authorized operator memory. Broader
service/package/log access is not implied by this source.

`Request`, `Result` and `Report` implement redacted `fmt.Formatter` for every
format verb, including `%+v` and `%#v`. This only guards ordinary diagnostic
formatting: explicitly reading a field or JSON-encoding the structs exposes the
selected identity/content. Integrations must never log, persist, or export those
serializations as diagnostic/attempt metadata. Report warnings and formatting
redaction are not substitutes for transport authorization or renderer safety.
Display messages as untrusted plain text, never executable HTML.

## Bounds and native API behavior

- At most 16 exact selections per call; one event handle is enumerated per
  selection. There is no broad event scan or lookahead formatting.
- At most 16 KiB of UTF-8 message text per result and 64 KiB across a report.
  Truncation respects UTF-8 rune boundaries and records `bounded` quality plus
  a fixed per-message/total-limit reason. Once the total budget is fully used,
  remaining selections are marked bounded without opening another query.
- Each message has a two-call `EvtFormatMessage` probe/fill sequence, with at
  most 32,768 UTF-16 units (64 KiB, including terminator) allocated. An oversize
  request or a growing native buffer produces a fixed buffer-limit failure,
  not unbounded retries. The subsequent UTF-8 output is separately bounded.
- The six-property metadata render allocation is capped at 16 KiB, and provider
  names at 256 UTF-16 units. Pointer values are decoded only as checked offsets
  into that native render buffer. Malformed UTF-16, embedded NULs, invalid
  lengths/types and absent required metadata fail closed.
- Query, event, values-context and publisher handles are closed on every exit,
  including cancellation and native errors. Query creation, use and cleanup
  stay on the same locked OS thread.
- The five-second budget is cooperative. `EvtNext` waits at most 250 ms (or the
  shorter remaining deadline). `EvtQuery`, `EvtRender`,
  `EvtOpenPublisherMetadata` and `EvtFormatMessage` expose no timeout argument;
  an in-flight synchronous call can exceed the budget. Context is checked
  between native stages. No goroutine or native handle is abandoned to claim a
  hard cancellation guarantee.

The adapter loads `wevtapi.dll` from the Windows system directory. Queries use a
NULL local session, fixed channel-path flags and a decimal record-ID-only XPath.
The selected, verified provider opens local registered publisher metadata with a
NULL archived-log path and locale zero (the current thread's locale). Only
`EvtFormatMessageEvent` is requested, with no caller-supplied insertion values;
the native formatter resolves event insertion values itself. Localized messages
can vary with the installed publisher resources and locale.

An absent publisher, message definition, locale/resource, or unresolved insert
is an explicit unavailable message. Partially populated buffers from failed
formatting are discarded. There is no XML/raw-data fallback or fabricated text.
Successful rows survive another row's failure, giving a `partial` report and a
non-nil joined error consisting only of fixed known errors. Native error text,
publisher resource paths and event content never enter diagnostic errors.
Consumers must inspect the report even when an error is returned, and must not
interpret `partial` or `bounded` as complete.

## Verification and outstanding gate

Portable fixtures cover six-field identity rejection before formatting, exact
record selection, source failures/missing publishers, bounded output, aggregate
read suppression, redacted diagnostics, cancellation, malformed native values,
UTF-16 probe/fill limits, invalid report states, and JSON validation round trips.
Source guards keep the native API set local/read-only and prove that the existing
metadata source has no message-formatting capability.

```sh
go test -race ./internal/windowseventcontent ./internal/windowsevents
go test ./internal/windowseventcontent -run '^$' -fuzz FuzzFormattedMessage -fuzztime 10s
go test ./internal/windowseventcontent -run '^$' -fuzz FuzzMetadataValues -fuzztime 10s
GOOS=windows GOARCH=amd64 go test -c -o /tmp/windowseventcontent-amd64.test.exe ./internal/windowseventcontent
GOOS=windows GOARCH=arm64 go test -c -o /tmp/windowseventcontent-arm64.test.exe ./internal/windowseventcontent
```

Cross-compilation and synthetic fixtures are not native Windows acceptance.
No real host log was read, event written, service altered, account granted
permission or publisher installed for these checks. Before release, a separately
authorized disposable Windows gate must select known synthetic Application and
System event identities, compare bounded message text against the expected local
publisher rendering, exercise missing publisher/record, denied access and
cancellation, and demonstrate same-thread resource cleanup on amd64 and arm64
where supported. Never print real event content or credentials in gate reports.
This candidate adds no automatic native smoke test or new public command.

## Official API references

- [EvtQuery: local session, XPath, same-thread query handle](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [EvtNext: timeout and event-handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext)
- [EvtOpenPublisherMetadata: local publisher, archived path, locale, cleanup](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtopenpublishermetadata)
- [EvtFormatMessage: insertion values and character-count buffer contract](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtformatmessage)
- [EVT_FORMAT_MESSAGE_FLAGS: event message versus XML](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_format_message_flags)
- [Microsoft message-formatting example and missing-message handling](https://learn.microsoft.com/en-us/windows/win32/wes/formatting-event-messages)
