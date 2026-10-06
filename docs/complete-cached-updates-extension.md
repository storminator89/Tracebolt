# Complete cached APT candidate rows

For an existing compatible installed agent, the [one-time inventory guide](guided-inventory-setup.md) groups full process/mount and cached APT consent into one local confirmation. It preserves the existing separate scope boundaries.

This source candidate extends the bounded [cached-update preview](cached-updates-extension.md)
with a separately consented, immutable full-known-candidate generation. It reuses
the package transfer state machine through a fixed cached-update codec. It does
not change the package, preview, process, mount or journal contracts. This document
is not permission to activate it on an endpoint; native Debian 13 / Ubuntu 24.04
and service/reboot acceptance remain separate gates.

## Exact meaning and limits

The source adapter routes only exact Debian 13/trixie and Ubuntu 24.04/noble identities; native compatibility is not established by fixtures. Its conservative configuration checks may reject otherwise ordinary APT configurations, including `Dir::Cache` settings, block comments or nested config directives. Those configurations remain explicitly unsupported; the reader never follows untracked configuration paths to make a result appear available. A narrow [Debian default compatibility exception](debian-cached-update-compatibility.md) accepts the exact flat installation-media and apt-listchanges defaults without weakening the tracked-source checks.
The scope is what the existing unprivileged agent can see, including its Linux
namespace limitations. One successful, rechecked cached-only operation supplies
both the unchanged 2 KiB / at-most-16-row preview and all known newer candidate
rows before preview trimming. The full generation includes up to 16,384 rows,
with bounded 128-row / 64 KiB chunks and the existing generation byte ceilings.
A manager page reads retained immutable data and never causes an endpoint query.

A completed generation means every declared known candidate row arrived intact.
Unknown comparisons stay explicit and candidate counts may be a lower bound;
completion does not mean all installed packages were comparable, up to date,
installable, unphased, available or free of vulnerabilities. Held packages remain
marked held. No repository URL, raw config, stderr, shell command or arbitrary
manager-supplied query argument is exported. No metadata refresh, download,
installation, service activation or permission change is performed. An unsupported OS release or APT configuration is a distinct `not_supported` failure in this full-update protocol, never a successful zero count.

The source reader remains synchronous, single-flight and read-only, with a
15-second collection ceiling. The complete extension attempts a capture no more
frequently than once per six hours. Each foreground cycle gives its serialized
transfer at most 20 cooperative seconds / 64 purpose operations, after the
existing system and installed-package stages. Optional transfer failures retain
pending work without changing successful metric cadence or blocking the later
overview/journal stages. Trusted local state or configuration failures still stop
reporting. Synchronous OS I/O requires an external supervisor for hard deadlines.

## Separate, default-off local consent

Preview consent never enables full-row collection or delivery. The full grant is
`tracebolt.complete-cached-apt-updates-local-consent.v1`, for extension
`tracebolt.complete-cached-apt-updates.v1` and exact scope
`agent-visible-complete-known-cached-apt-candidate-rows`. It is bound to the current
validated v3 sender identity, manager, transport, profile and certificate through
the existing sender binding. It cannot enable old/basic/v2 identities.

Only after deciding to grant this scope, run as the existing dedicated service
account after stopping its sender. Use the actual protected config and numeric
service UID:GID; these are placeholders, not installation commands:

```sh
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --complete-cached-updates-consent preview
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --complete-cached-updates-consent enable --ack-complete-cached-updates
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --complete-cached-updates-consent disable
```

These modes cannot be combined with reporting, enrollment, validation or another
consent mode. Preview only explains the scope and current status. Enable requires
an explicit acknowledgment of all known rows, names, architectures, installed and
candidate versions, holds, comparison gaps, original metadata age and the fixed
six-hour cadence. HTTP-test remains plaintext with an unauthenticated manager.
The helper does not start a service, contact the manager or read package sources.

An enabled full extension has its own fixed `cached-updates` spool and derived
binding. Its protected consent sidecar is `complete-cached-updates-consent.json`.
Only the explicit stopped-service enable action can initialize an absent full
spool. Existing package/metrics/system state and preview consent remain unchanged.
Existing full state is validated, never reset. An existing consent with a missing
spool, foreign/corrupt state, or an unfinished initialization marker fails closed.
Do not edit/remove internal state to recover it; investigate the exact failure.

Absent, malformed, unsafe, foreign or uncertain full consent prevents both source
access and opening the full spool. Consent is rechecked before capture, after
capture, and before every transmission, including retries and status recovery.
Disabling leaves exact pending bytes and consumed sequence floors dormant; a
fresh explicit full grant is needed to resume them. It does not erase already
received manager data or refresh its original retention age. Preview consent is
independent and must be disabled separately if desired.

## Durable transfer and truthful age

The request/receipt and signature domains are separate from installed packages,
using `/v3/agent/cached-updates/`. A fixed update codec shares the existing state
and bounded recovery algorithm; it cannot choose arbitrary schemas or commands.
Retries preserve the exact manifest, chunks, sequence, original capture time and
index modification time. HTTP signature time may advance without changing those
bytes. A completed retained generation ends that burst, avoiding immediate
recapture after restart. Failed/incomplete sources produce a failure attempt,
never a successful empty generation. Sequence allocation is durable before any
source access, so interruption cannot reuse a consumed sequence. A first Begin
that arrives after source retention is durably refused under its exact identity
and binding, then retired through the normal status/abort acknowledgment exchange.
It never becomes an empty or newly dated generation. Exact latest completion
receipts survive payload expiry and cleanup so a lost acknowledgment remains
recoverable; this does not restore expired rows.

Source freshness and observation age are separate. Index mtime cannot prove a
successful repository refresh. A source age of at least 48 hours is marked stale;
otherwise freshness is unknown. Completing, delivering, retrying or viewing an
old generation does not make it newly captured. Manager access control, atomic
promotion, original-age retention and generation-pinned paging are enforced by
the matching manager implementation.

## Fixture verification and remaining gates

The focused source tests use synthetic inventories only: 1,100 candidates survive
preview trimming, known zero differs from unknown comparisons, failures expose no
prefix, and preview/full consent reject each other's versions and scopes. Sender
fixtures use typed mock receipts over local TLS and signed HTTP; they cover
multi-chunk restart replay, original age,
withdrawal during capture/transfer, independent durable floors, six-hour cadence,
and optional transport failure isolation. A direct production-sender → actual enrolled ingress → SQLite test covers both TLS and signed HTTP: 1,100 synthetic candidates, a lost committed append acknowledgment, sender reopen without recapture, manager database reopen, and all 16 bounded pages with held/unknown counts and original ages intact. Separate actual authenticated ingress/store tests transfer and atomically promote 1,201 synthetic rows, reject partial completion and revoked identities, preserve exact receipts, and read every retained row through bounded paging. Manager fixtures cover 2,300-row search, quotas, expiry, cleanup, lost completion acknowledgments and independent floors. Actual Go-encoded DTO fixtures are validated by the frontend, whose paging tests traverse 1,213 rows and continue search beyond row 2,048. None of these synthetic checks establish a populated native endpoint result. CLI/loop tests cover pre-access identity
checks, exact acknowledgments and bounded content-free status metadata.

These tests do not read a real APT cache, install packages, grant permissions,
start a service or prove OS deployment/reboot behavior. Actual ordinary-user
Debian 13 and Ubuntu 24.04 cache comparisons, runtime measurements and deployment
acceptance must be recorded separately before claiming native readiness.
