# Windows Event Log metadata source candidate

`Collect(context.Context, []string, int)` is an explicit local read. It permits
only the exact `Application` and `System` channels, at most once each, and 1–100
events per channel. There is no default channel, background collection, custom
query, file input, remote session, subscription, bookmark, command or write API.
The caller must separately authorize collection; this package grants no consent.

The native adapter uses `windows.NewLazySystemDLL("wevtapi.dll")`, a local
`EvtQuery` with fixed channel/reverse flags, and a NULL query selecting all records.
It renders only six fixed `Event/System` properties: record ID, 16-bit event ID,
level, provider name, UTC timestamp and channel. The restricted values context is
deliberate: rendering the entire System context would also retrieve machine names
and security identifiers. No message formatting, XML rendering, EventData,
UserData, username, SID or log-content export is implemented.

Each report supplies source, capture time, quality and per-channel results. An
exhausted query is complete; an extra handle beyond the limit proves truncation
without rendering its metadata. Source errors produce a fixed reason and partial
or unavailable quality rather than fabricated rows. Absent or malformed required
properties fail closed. No raw OS error text or event values enter diagnostic
errors. The render allocation is capped at 16 KiB per event; provider names are
capped at 256 UTF-16 units. Buffers and native handles are not retained in reports.

At most `limit + 1` handles are enumerated and `limit` events are rendered per
channel. Handles are closed on all exits and kept on their creating OS thread.
The five-second collection budget is cooperative, with a maximum 250 ms wait in
each `EvtNext`. Windows provides no timeout argument for synchronous `EvtQuery`
or `EvtRender`; an in-flight call cannot be forcibly bounded by this adapter.
No goroutine is abandoned to pretend cancellation finished. Query completeness
does not imply an immutable snapshot or that older/cleared events still exist.

## Verification

Portable fixtures, malformed native-value buffers, bounds, cancellation, error
sanitization and source-shape tests run with:

```
go test -race ./internal/windowsevents
go test ./internal/windowsevents -fuzz FuzzMetadataValues -fuzztime 10s
GOOS=windows GOARCH=amd64 go test -c -o /tmp/windowsevents.test.exe ./internal/windowsevents
```

Cross-compilation and fixtures are not native acceptance. The opt-in Windows
smoke test reads at most three metadata rows from each allowed channel, never
writes an event, and never prints telemetry. On an explicitly approved disposable
Windows VM, set `TRACEBOLT_WINDOWS_READONLY_NATIVE=1` and run:

```
go test -run TestNativeWindowsEventMetadata ./internal/windowsevents
```

Ordinary Windows tests do not read real logs. The opted-in gate requires at least
one successful allowed-channel query and at least one rendered, validated event
overall. It tolerates an empty single channel or explicit access denial only for
the other channel. Unavailable sources or malformed native metadata fail the
gate. Empty channels remain valid exhausted collection results, but two empty
channels cannot pass a rendering gate. A denied channel is not native acceptance.

## Official API references

- [EvtQuery, including local sessions and thread affinity](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery)
- [EvtNext timeout and handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext)
- [EvtCreateRenderContext selected values](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtcreaterendercontext)
- [EvtRender values and buffer contract](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender)
- [EVT_VARIANT layout](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ns-winevt-evt_variant)
- [Rendering specific System values](https://learn.microsoft.com/en-us/windows/win32/wes/rendering-events)
- [System property types](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_system_property_id)
