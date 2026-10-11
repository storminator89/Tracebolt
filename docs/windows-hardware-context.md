# Windows hardware and power context: source candidate

This feature is not in the published Windows preview. Actual unchanged
LocalService reads, Windows 11/Server provider coverage and fresh Setup acceptance
are unverified and deferred until the missing Admin-data work is complete.
No host read, installation, firmware access/change or release follows from source
fixtures, compilation or browser screenshots.

## Useful fields and their exact sources

The private Device view shows a compact manufacturer/model, physical chassis
serial, BIOS and power summary. BIOS serial stays in optional source details.

- Win32_ComputerSystem: Manufacturer and Model only.
- Win32_SystemEnclosure: SerialNumber only. This is a manufacturer-supplied
  physical-enclosure label, not a validated unique machine identifier.
- Win32_BIOS: Manufacturer, SMBIOSBIOSVersion, ReleaseDate and SerialNumber only.
  BIOS serial describes the software element; it is not substituted for chassis
  serial. ReleaseDate retains fully specified validated DMTF text. Missing,
  wildcard or malformed dates stay empty/unavailable, never a guessed date.
- GetSystemPowerStatus: AC line state, battery presence, charging, charge percent
  and estimated remaining seconds. No-battery is distinct from unknown. Flag 255
  is checked before bit 128; flag 0 is legitimate noncharging midrange. Percent 255
  and time0xffffffff are unknown. Remaining time stays unknown on AC power.
  These are system estimates, not per-battery health, capacity, cycles or runtime
  promises.

Primary API references:
[ComputerSystem](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem),
[SystemEnclosure](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure),
[BIOS](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-bios),
[power status](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-system_power_status).

## Consent and bounded runtime

`windows-hardware-context-v1` is an independent default-off local grant with its
own protected `-hardware-context` sibling store. It names identifying serial
metadata and separate HTTP-test plaintext risk. Fresh Setup is still one concise
Read admin profile with initially unchecked consent and optional detail. Its new
exact thirteen-scope consent v6, outer receipt 4 and bodyless capability v2 route
must match; historical v1-v5 grants/receipts retain their exact meanings.
See [fresh Setup](windows-read-admin-setup.md). No manual per-feature setup
command is added as a requirement and no migration path is introduced.

Each of four fixed sources runs in its own current-executable worker, under the
existing token. The child independently rereads protected installed identity and
grant before and after its read. It receives only opaque binding, grant,
generation and original capture time over bounded private pipes; no credentials,
configuration path, arbitrary query or inherited environment. COM activation
uses the existing locked-thread, no-impersonation, High/System-integrity check;
it never elevates or repairs a denied source.

The three fixed local CIMV2 queries are semisynchronous/forward-only and call
Next at most twice, accepting at most one row. Unexpected multiplicity, including
multiple enclosures, is unavailable/bounds rather than a claim of one unique
serial. BSTR length is checked before copying, malformed UTF-16 rejected, labels
capped at 128 UTF-16 units and serials at 64. The complete snapshot is at most 6 KiB.
Each provider gets at most one second and a fair share of the remaining parent
budget after reap reserve. Timeouts preserve siblings. Parent cancellation kills
and synchronously reaps the owned child; it cannot stop provider-service internal
work. The hardware scope joins the existing optional-source rotation/reserve.

## Transport, private retention and exclusions

Wire v12 requires hardware and permits earlier explicitly granted envelopes.
Earlier wire versions and pending retry bytes remain unchanged. Sender and
manager validate exact schema, scope, grant, generation, capture, finite source
states and independent grant IDs. Revoked/replaced authority never retries the
old hardware body. Frame fitting retains base identity/bindings and granted
context envelopes under the existing 72 KiB limit.

Only the private authenticated Windows inventory view exposes these fields.
Useful prior scope captures keep their original grant/generation/time and expire
at 24 hours; latest failure remains visible. Missing/replaced grants and revoked
identity clear access. The existing 80 KiB optional retention table is unchanged:
if independently full scopes exceed that ceiling, evict the oldest whole cached
capture rather than merge fields or alter age. Current and prior views both obey
operator-session expiry and cancellation.

No AI/provider export, notifications or basic observation projection is added.
Hardware UUID, asset tags, raw SMBIOS, license/product/recovery keys, credentials,
remote WMI, PowerShell, arbitrary enumeration, firmware writes, driver/provider
installation, privilege/account/ACL/network changes and remote desktop are out
of scope. Source fixtures are synthetic; native acceptance remains a separate
explicit exact-artifact gate.
