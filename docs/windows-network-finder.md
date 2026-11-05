# Find retained Windows network endpoints

Source candidate, 5 November 2026. The device's existing **Network → Adapters &
endpoints** view now supports local search, filtering and paging of its already
consented network snapshot. It adds no fleet panel, API, host read or grant.

## Technician workflow

1. Open Network on an authorized Windows device and inspect the capture date and
   coverage first. Older, partial and trimmed captures keep their warnings.
2. Search any numeric address, port, API PID, protocol, IP version or TCP state.
   **Any value** and **Address** use literal case-insensitive substring matching.
3. For a specific socket or attribution, choose **Exact local port**, **Exact
   remote port** or **Exact API PID**. These accept whole decimal numbers within
   the actual field range, including genuine zero. An empty query applies no
   numeric restriction. Invalid input shows a validation message, not a false
   no-match result. UDP PID zero is unavailable, never process zero.
4. Narrow to TCP listeners, established TCP, all TCP or UDP, and optionally IPv4
   or IPv6. Sort numeric ports or PIDs, or return to original capture order.
   Unavailable/inapplicable values remain last in either direction. Duplicate
   API tuples are not collapsed. At most 25 retained rows appear per page.
5. **Clear endpoint filters** restores every control and page one.

Only retained rows can match. A no-match result does not prove that a port is
free or an endpoint absent. Listener rows are observations, not firewall or
reachability tests. API PIDs do not establish an executable identity, and this
view never joins another capture's process rows. Missing peers remain not
applicable; UDP has no TCP state. Source-observed counts, lower-bound qualifiers
and retained counts stay separate from the filtered page's matching/visible
counts. Collection remains capped at 64 retained rows and 12 KiB.

The practical comparison is Datto's documented
[port-conflict troubleshooting](https://rmm.datto.com/help/en/Content/Troubleshooting/Agent/KB360021596071.htm),
checked 5 November 2026. That guide uses live commands to inspect port/PID
attribution. This feature only makes Tracebolt's existing passive snapshot easy
to inspect; it does not implement those commands, live Datto tools or the
process-name join.

## Privacy and lifetime

The original [network endpoint contract](windows-network-endpoints.md) remains
unchanged. Search, sort and filter operations stay in component memory. They
make no requests and do not write URLs, storage, clipboard, exported files,
notifications or external AI inputs. Refresh still uses the existing private
inventory resource; neither filters nor refresh initiate host collection.

Controls survive a reread of the same device/grant/generation/capture only.
Changing device, operator session, generation, grant or capture resets them.
Leaving the view, switching network sources, losing focus, hiding the page,
losing access, receiving an error, original source/base expiry or a clock
inconsistency clears private rows and filters. A pending response cannot restore
suspended data. Existing resource polling, strict validation and conservative
capture/manager-clock authority remain unchanged.

## Verification boundary

Focused pure/DOM tests cover exact fields, numeric bounds, IPv6, nulls/zeros,
source immutability, duplicate order, pagination, reset and interrupted private
lifecycle. Existing network/inventory tests, TypeScript and production build are
required. No browser automation or native Windows acceptance is claimed. This
source change does not resolve the unrelated fleet-capture verifier regression
and is not a release, deployment or permission grant.
