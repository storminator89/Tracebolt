# Cached APT update observations (first-stage candidate)

Status: unpublished, default-off source candidate based on
`424bff2f8f9a10ca1ba68a889a71039b2bd7a525`. This is a bounded preview, **not the
completed all-update inventory feature**. A successful enumeration records exact
candidate and hold totals, but only a 2 KiB / at-most-16-row candidate preview is
retained. Omitted candidate rows are not available elsewhere. Truncation is always
`partial`, `truncated=true`, and `item_limit` or `byte_limit`. Complete generation
transport and authenticated paging for every candidate remain a separate gate.

## Collection and meaning

Only exact Debian 13 / `trixie` and Ubuntu 24.04 / `noble` identities are routed to
the adapter. Fixture coverage is not native acceptance. Mint, Debian/Ubuntu other
releases, RPM distributions, Windows and macOS remain unsupported. The scope is
the agent-visible namespace; it must not be called host-wide in a container.

The existing protected package reader captures installed/incomplete dpkg rows
from the standard local database. Only fully installed rows enter this query.
A fixed `/usr/bin/dpkg-query --admindir=/var/lib/dpkg --show --showformat=...`
selects name, version, architecture and the three status fields; the wanted
`hold` state is retained. Installed rows must agree with the protected reader.
Fixed `/usr/bin/apt-cache ... policy name:architecture ...` batches select native
installed and candidate versions from the already available local package lists.
Batches contain one architecture, at most 128 names and at most 32 KiB of package
arguments. Package/version/architecture strings have bounded validated grammars;
there is no shell, caller-provided path, arbitrary command or manager-supplied
query argument.

Both APT binary cache paths are explicitly empty. Standard status, list, source
and preference paths are fixed. Existing native pin/default-release policy is
used; no repository is added or selected by the manager. The environment is
allowlisted, including `LC_ALL=C`, with no inherited `APT_CONFIG`. Output is
limited to 8 MiB per native command, with a 4-second command deadline and bounded
pipe-wait. Raw stderr, repository URLs, credentials and policy table text are
never exported. Only installed/candidate fields are retained from policy output.
There is no `apt update`, package installation, download, network fetch, service
activation, package-manager repair or remediation operation.

The installed source is bounded to 16,384 rows. The collector has single-flight
admission and a 15-second own ceiling; the optional runtime sub-attempt is tighter
(at most 5 seconds, reserving about one second of the parent's existing deadline
for delivery). A slow update extension reports unavailable/timeout instead of
cancelling an otherwise valid system observation. Native-source reads are
synchronous with cooperative cancellation, like the existing protected package
collector; no detached goroutine abandons an in-flight filesystem read.

Missing dpkg data or package indexes, permission failures, malformed output,
source changes, timeouts and work limits are unavailable with null counts, never
zero success. Missing native candidates or unsupported Debian comparator values
are unknown comparisons; candidate totals then form a lower bound. A successful
zero means only no newer native candidate in the checked existing cache.

The existing pure Debian comparator preserves epoch, tilde and revision ordering.
A higher candidate is `candidate_only`; a higher held candidate is `held`.
`installability` is always `not_evaluated`. Dependencies, phase eligibility,
entitlements, repository reachability, package origin/authenticity, active kernel
state, reboot need and CVE applicability are not determined. In particular, zero
candidates is not evidence of security compliance or that all vulnerabilities
are fixed.

## Metadata age

Metadata age is explicitly the oldest local binary-Package-index modification
time, considering supported compressed and uncompressed names in the standard
list directory. Release-file dates, repository URLs and arbitrary file contents
are not exported. Root-owned regular files and protected directory/config/status
metadata are checked; Release/InRelease files are pinned separately because they affect native policy. APT config files are read under a 64 KiB per-file / 2 MiB total bound; `#include` / `#clear` directives and standalone `Dir` / `RootDir` tokens are conservatively unsupported, including mentions in comments or strings. Block-comment markers are also rejected because APT can concatenate surrounding text (`D/**/ir`). This catches flat and nested main-config/base-path redirection before command-line overrides are applied. It also rejects harmless `Dir::Cache` customization, including common container defaults; supporting those safely requires a bounded APT-scope parser rather than incomplete flat-key matching. External configuration cannot evade the fixed source checks through these supported directives. Symlinks, unsafe ownership/modes and observed changes fail
closed. Successful re-reading never refreshes the source timestamp.

A modification age of at least 48 hours is conservatively marked `stale` by this
adapter's local policy. Otherwise source freshness is still `unknown`: a recent
mtime cannot prove a successful refresh, completeness of configured repositories,
signature validity or upstream freshness. No `fresh` source value exists in this
schema. The report's independent `fresh` / `stale` observation age is still the
existing system observation's 120-second window, with original 24-hour retention.

## Explicit opt-in and authenticated path

The extension follows the existing endpoint-display consent precedent. It uses
an already activated `managed-operations-v3` identity, with a protected local
sidecar bound to its current sender binding (device, leaf certificate, manager
origin, transport and collection profile). Both the manager and agent must include this new wire version before opt-in; an older manager rejects it and cannot acknowledge extension reports. No basic/v2 profile can acquire this
scope, no identity is silently relabelled, and no missing ledger is initialized.
A manager upgrade alone performs no additional APT reads.

Local administration requires the existing service owner, the explicit numeric
UID:GID guard, valid existing handoff/state, and a stopped sender ownership
lease. Preview does not collect, contact a manager or write a grant. The new
modes cannot be combined with reporting, enrollment or another consent mode.

Manual commands, only after the operator has decided to change the local grant:

```sh
# Use the actual protected config path and actual service account UID:GID.
# Run as that existing service account after stopping its sender/service.
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --cached-updates-consent preview
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --cached-updates-consent enable --ack-cached-updates
lan-agent --config /actual/agent.json --service-identity UID:GID \
  --cached-updates-consent disable
```

These are documentation templates, not an executed grant or a promise that a
published binary contains these flags. Stop/start/service-account switching
remain deliberate separately authorized operator actions. Preview exposes the
exact scope. HTTP-test content is unencrypted and its manager is unauthenticated;
use only the existing explicitly acknowledged disposable test configuration.

The strict system v3 frame adds `cachedUpdates` and its exact consent scope,
optionally coexisting with the prior endpoint-identity pair. Existing v1/v2 bytes
and body caps are preserved. Original durable system sequence, generation,
exact-body digest/receipt, activation, certificate, replay and revocation rules
apply. Consent is rechecked before capture and immediately before send. Removing
it discards a retained extension request without reusing its sequence floor.
A local declaration is not OS-attested proof of administrator consent.

One optional snapshot is retained in existing system authority metadata under
its unchanged 16 KiB cap. Ordinary reports without this extension never renew its
age. Expiry cleanup, revoked/expired identity restrictions and operator session
checks apply. Disabling the endpoint does not delete an already delivered report
or remotely confirm the current local grant state.

GET `/api/devices/{stable-device-id}/inventory/cached-updates` is a bounded,
operator-only same-origin read. It never starts a collection or refresh. The
Packages tab renders escaped inert text, observation age, independent metadata
age, installed/candidate versions, holds, unknown status and preview truncation.
Reports do not enter general Device identity, AI evidence, routing, shell commands
or public feeds.

## Verification boundary and remaining work

Automated coverage includes both declared release fixtures; epoch/tilde/native
candidate semantics; holds and zero/unknown/missing/stale paths; strict JSON and
counter overflow; command-argument rejection; consent/admin guards; old wire
compatibility and coexistence; authenticated ingest/replay/revocation; independent
retention and expiry; CLI refusal paths; operator API guards; bilingual UI,
bounded response parsing, session expiry, late responses, failed refresh and
monotonic observation-age behavior.

No native populated Debian 13/Ubuntu 24.04 endpoint acceptance, OS/service change,
real local grant, package refresh/install, deployment or publication is established
by these fixtures. Before operational support, compare results on both actual
supported OS versions using their existing local cache, ordinary service-owner
permissions, holds, pinning/phasing and interrupted/changed sources; observe that
native cache files remain unchanged. Keep absent metadata explicitly unavailable.

To meet the user's complete-update requirement, introduce a distinct immutable
full candidate generation with authenticated bounded chunks, durable consumed
floors, atomic complete promotion, original-age retention and bounded operator
paging/search. Reuse the existing full-package/overview patterns without changing
old contracts or making this 2 KiB preview masquerade as complete data. Complete
coverage also still needs separately implemented advisory assessment; this change
contains none.

Primary references checked 2026-10-05:

- [Debian trixie apt-cache](https://manpages.debian.org/trixie/apt/apt-cache.8.en.html)
- [Ubuntu noble apt-cache](https://manpages.ubuntu.com/manpages/noble/man8/apt-cache.8.html)
- [Debian trixie dpkg-query](https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html)
