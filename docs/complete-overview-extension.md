# Complete visible process and mount overview

For an existing compatible installed agent, the [one-time inventory guide](guided-inventory-setup.md) groups full process/mount and cached APT consent into one local confirmation. It preserves the existing separate scope boundaries.

This source adds full-generation process and mounted-filesystem views to an
existing activated Linux `managed-operations-v3` device. It is default-off until
an administrator explicitly enables its local scope. Existing package, metric,
system, hostname and journal identities and counters are preserved. No new
manager, invitation, enrollment or additional OS privilege is required.

## What the overview means

- Processes retains every successfully enumerated visible PID. Names, parent
  PID, state, resident bytes, cumulative CPU seconds and thread count are shown
  where available. Denied, exited and invalid fields retain an explicit outcome.
  Command lines, environments, usernames and file contents are excluded.
- Mounts retains every successfully enumerated visible mount. Measured local
  filesystems precede unavailable local, memory-backed, remote, unclassified
  and virtual mounts. Capacity is not summed across overlapping filesystem
  groups. N/A, denied, unsafe-to-measure and unavailable are distinct states.
- Both views describe the agent's Linux namespaces. An installed systemd
  sandbox can expose a different `/home` or mount set than the host. This is
  neither physical-disk discovery nor universal host visibility.
- Software overview totals come from a validated completed dpkg generation.
  The older sample remains secondary. Snap, Flatpak and manually installed
  software are not covered by a complete dpkg count.

Process names, mount paths and filesystem labels may be sensitive. The exact
local acknowledgement includes this scope, destination binding and the fixed
60-second capture cadence. HTTP-test delivery is unencrypted and does not
authenticate the manager. No overview rows enter AI packets or exports.

## Local administration

Upgrade manager and agent to a compatible reviewed version before enabling.
The existing official pilot.2 binaries do not implement this command. A source
checkpoint alone does not change the active download-release pin.

Stop only the existing sender, then invoke the selected `lan-agent` as its
existing nonroot numeric UID/GID with supplementary groups cleared:

```sh
lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --complete-overview-consent preview

lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --complete-overview-consent enable --ack-complete-overview

lan-agent --config ABSOLUTE_EXISTING_AGENT_JSON --service-identity UID:GID \
  --complete-overview-consent disable
```

These are interface examples, not a root deployment script. Inspect the preview
and restart the same service after the administration phase. The commands do no
collection or network requests and do not create an account, change groups,
install a service or grant permissions. The existing ready/config/certificate
and all required ledgers are validated under the stopped-sender owner lock.

First enable creates two new bounded private sequence domains, then publishes
consent only after both are durable. It never adopts one existing half or resets
an uncertain initialization. Preserve any failed/partial state for inspection.
Disable suppresses subsequent capture and delivery, preserving dormant pending
bytes and consumed floors. Previously delivered generations retain their original
ages and expiry; local disable is not immediate remote erasure.

## Delivery, retention and failure

One synchronous capture feeds independent process and mount generations. Chunks
are at most 128 rows/64KiB. Each attempt shares one cooperative 20-second,
64-operation transfer budget across both sections. Exact retries do not recollect
or refresh timestamps. All retained work drains before a new capture; successful
metrics and the journal stage continue when overview delivery alone fails.
Trusted local state/configuration failures still stop an unsafe sender.

Promotion is atomic only after the declared row count and digest validate.
A failed section cannot replace the last completed section with a prefix or
false zero, and cannot prevent its successful sibling from being shown.
Independent generations and original capture intervals are displayed explicitly.
A successful zero enumeration differs from unavailable or failed collection.

The existing manager store gains an explicit add-only overview schema; this does
not enable an endpoint. Older binaries may reject the extended schema; do not
delete tables, rewrite schema versions or reset identity to force a downgrade.
Pages are authenticated and generation-pinned, at most
100 rows with a 256KiB encoded response ceiling. Search is literal over bounded
scan windows; an empty nonterminal page is a continuation. Collection retention
is 24 hours; cursor and retired-generation grace are 15 minutes. A trusted manager
maintenance loop reclaims only eligible noncurrent data in small batches while
preserving current rows, identity, receipts and replay floors.

Capture/transfer/database ceilings are explicit failure limits, not claims that
all maximum-sized devices fit simultaneously or finish within one burst. See
[the capture contract](complete-overview-capture.md),
[normalized storage](../internal/enrollmentstore/OVERVIEW.md), and
[the UI contract](full-inventory/complete-overview-ui.md).

## Verification scope

Inert fixtures exercise complete enumeration, field gaps, 32 virtual mounts with
the useful root volume beyond the former prefix, independent promotion,
restart/exact retry, explicit consent/disable, paged search and expiry. A generated
identity/real mTLS and signed-HTTP test connects the native sender and durable
store with 513 invented process rows and 300 invented mounts. It loses an accepted
append response, restarts the sender, reads every page and verifies revoked exact
replay rejection without recollection. No real source or installed service is
used by that test. Hosted native and browser outcomes are separate release gates.
