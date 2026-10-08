# Windows Logs: browse the accepted header sample

This UI-only source slice exposes the existing Windows event-header snapshot in
its own **Logs** tab in the shared device dashboard, alongside the existing
Health summary. Health offers an explicit shortcut to Logs. It introduces no
collector, endpoint read, wire/schema/API change, grant, subscription, bookmark,
source-history retrieval, raw content or external-AI path.

Only the previously granted `windows-application-system-event-headers-v1` sample
is displayed through the existing authenticated Windows inventory read. The
existing cap remains 16 headers per Application/System channel and 6 KiB. The
same six headers are shown: event time, channel, native level, provider, event ID
and the full decimal record ID. Unknown/reserved levels remain explicit.

Channel, exact level, literal case-insensitive provider text and exact event-ID
filters operate only on this accepted sample. Ten-row pages are local sample
pages, never a continuation request. The visible boundary explains that older
events are not fetched; original capture time, per-channel denial, partial reads
and omitted rows remain visible even when filters match no rows. Refresh checks
the latest accepted report without triggering a native read. Capture freshness
and private-data expiry are inherited unchanged from the existing resource.

Rows are ordered by event timestamp, including sub-millisecond fractions, then
channel and full-width record ID within a channel. This display ordering is not
a cross-channel source cursor or a claim of complete historical coverage.

Repeated tab selection and device metadata refresh preserve controls and page.
A refresh of the same generation preserves the selected page; a new generation
starts at page one and keeps the filters. Changing filters starts at page one.
Leaving the tab, changing the device or operator session, losing access, hiding
or navigating the page, expiration or an accepted report without event headers
discards local filter text. No sample rows are cached by
the panel or placed in browser storage. The existing resource continues to clear
rows on errors, suspension, session loss and original expiry. EN/DE labels,
keyboard tab navigation, touch controls and stacked narrow-screen table labels
use the existing shared layout.

## Source verification boundary

Synthetic DOM tests cover filters, page bounds, same/new-generation refresh,
original-age expiry, partial/denied/empty samples, full record IDs, nanosecond
ordering, literal provider text, private-field rejection, Security rejection,
device/session navigation, interruption and Linux read-route isolation. Existing
Linux service-to-Logs and keyboard-tab fixtures must remain green. The additive
hosted Windows case includes synthetic EN/DE desktop/mobile Logs navigation,
filters, page bounds, poll-focus retention and original-age expiry. Its pure
fixture/source contracts run locally; the browser case itself is not run here.

No native event source, real endpoint, host change, browser launch, installation,
publication or deployment is part of these tests. Native/browser acceptance for
this exact source remains a separate gate. The existing Windows installation
approval does not grant messages, XML, EventData, Security logs, additional
channels, persistent permissions, source pagination or remediation.
