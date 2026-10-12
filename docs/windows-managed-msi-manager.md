# Central managed MSI: manager source candidate

This fresh, default-off source feature uploads **one exact x64 machine MSI**,
delivers it to **one separately granted Windows endpoint**, and authorizes at
most **one installation attempt**. It is a new `windows-managed-msi.v1` domain.
Prepared MSI v1, its bytes, foreground workflow and existing grants remain
independent. Nothing here promotes an observation, WUA, service-action or prepared
package grant. Source tests use inert synthetic bytes and establish no native
acceptance, package choice, deployment or installation.
For fresh upload-once fleet configuration and the manual per-device worklist, see
[Windows fleet MSI](windows-fleet-managed-msi.md). Its explicit v2 setup/registry
never adopts or converts this singleton v1 state.

## Operator workflow

The Software view offers an English/German **Upload & deliver MSI** panel:

1. Select a local MSI and its fixed public review JSON. The review contains only
   `package` (the same closed Selection fields as prepared MSI) and the separate
   `nativeAcceptanceDigest`. Hash, size and the compound-file signature are
   checked during bounded chunk upload and explicit completion. Manager validation is byte custody, not native MSI
   metadata or publisher/safety proof. Upload approves neither package terms,
   delivery nor installation.
2. Check the initially unchecked delivery acknowledgement for the exact device
   and package. The original delivery permit expires within 24 hours and is
   clamped to the current authenticated leaf and original local grant.
3. Once the dedicated endpoint service reports protected import, explicitly
   review the exact package, custom-action risks, terms and package-specific
   native-acceptance evidence. Check separate initially unchecked package, terms
   and maintenance-window acknowledgements. The maintenance window lasts at most
   ten minutes and asserts other install/update/service work has been paused.
4. The executor checks native MSI metadata and readiness. A fresh, initially
   unchecked named-operator approval can authorize one installation only within
   the original 60-second readiness deadline. Focus/session changes and expiry
   clear approval. A lost mutation response requires reading saved status;
   the UI does not send a replacement request.
5. Durable signed outcomes retain exact 0/3010/1641/1618 and other failure codes,
   unknown-return truth, independent machine-registration verification and
   uncertainty. No result read retries installation or claims rollback.

The separate deployment service runs as **LocalSystem**, with extensive local
rights and machine-account network access. MSI custom actions can run arbitrary
code, reach networks, change services and disrupt applications. This is **not a
sandbox**. Hashes establish byte identity, not safety or offline behavior.

Deployment mode excludes other Tracebolt mutators on this same endpoint;
observation remains available. Manager and endpoint setup refuse reciprocal
prepared-MSI, WUA and service-action coexistence. This is partial management,
not a shared durable Windows mutation fence. Shared mutation fencing is the next
increment. External installers and other administrators still require operational
coordination; the maintenance acknowledgement is not an OS-wide mutex.

## Protected manager custody and storage

A create-only spool is fixed beneath the configured StateDirectory at
`windows-managed-msi-spool/artifact.msi`. Names are server-selected. A durable
SQLite upload intent precedes artifact writes. Each upload frame contains at
most 32 KiB raw bytes with its exact index and digest, fitting 64 KiB encoded.
A pending chunk is durable before append/fsync, then its offset/prefix checkpoint
is committed before acknowledgement. Exactly matching unacknowledged tail bytes
can resume the same pending chunk after interruption; foreign or changed bytes
never can. An explicit completion verifies the whole exact hash before marking
the artifact uploaded. There is one exclusively
created, owner-only, single-link regular artifact. Partial and complete bytes use
the same inode and are capped together at **128 MiB**. Linked artifacts, changed bytes
and replacements detected by process-lifetime pinned identity checks are rejected;
no artifact is overwritten or reset. The manager does not persist a Linux inode
receipt across restart. Reopening validates private single-link custody and exact
content against the durable intent, prefix and pending-chunk checkpoints. A
byte-identical replacement by the trusted owner between processes is therefore
not distinguished from the original inode. The native endpoint separately retains
its required durable original-object receipt.
A partial upload may continue only under its original immutable intent, exact
pending bytes and durable prefix; no replacement package or transfer is created.
Protected parent traversal rejects symlinks and unsafe ownership/modes. File and
parent fsyncs precede success; process-lifetime object identity is checked again
after storage waits. Restart recovery uses the content/checkpoint checks above.

No package blob or chunk enters SQLite. Fresh reciprocal metadata/credential
markers are in `enrollment_windows_managed_msi_*`; existing database and SQLite
page bounds, including the **192 MiB** Windows enrollment cap, are unchanged.
Each record is bounded to 256 KiB and there can be exactly one managed record.

The endpoint receives only fixed canonical POST operations under
`/v1/windows-managed-msi/{poll,chunk,report}`. Chunks contain at most 32 KiB raw
bytes, at most 4096 per artifact, and fit a 64 KiB encoded frame. No caller
filename, URL, range request, proxy route, redirect or compressed body is accepted.
The complete spool hash is checked on first release after restart; cached bounded
per-chunk hashes then verify each exact chunk with pinned object identity and
unchanged metadata. Original delivery permit bytes may be re-polled to resume the
same transfer; no signature, deadline, package or transfer is renewed.

Readiness and installation permits are released once, after durable claims.
Lost install responses stay uncertain. A readiness challenge that expired
without installation may be replaced only by a fresh explicit package/terms/
maintenance review with a strictly increasing durable sequence. No automatic
re-signing or installation replay follows. The endpoint's permanent attempted state prevents
reconstruction/replay after a process restart. Signed durable result bytes can be
reported idempotently while current authority remains valid. A terminal signed
delivery intervention receipt may arrive after its original delivery deadline;
it grants no chunk access, new transfer, readiness or installation. Successful
import and readiness reports remain bounded by their original deadline.

Each manager state change and byte release checks the current TLS leaf,
revocation, original enrollment identity, separate grant, absolute expiry,
monotonic time floor and currently named operator capability. Checks run again
after spool/SQLite/configuration waits and immediately before release. Renewal
never extends a permit, review, grant or capture timestamp. A changed current
leaf fences the original transfer/permit in this conservative first slice;
there is no replacement or re-dating to resume across renewal.

## Fresh explicit manager setup (source only)

Provision the separate operator capabilities `windows_managed_msi_deliver` and
`windows_managed_msi_install` in protected operator configuration. Neither implies
the other, and no existing operator receives either automatically.

The new source command `windows-managed-msi-manager-setup prepare` accepts
`--lan-config`, `--enrollment-config`, `--device-id` and absolute `--expires-at`.
It prints a read-only plan. Explicit apply requires `--apply`, the exact
`--approve-plan sha256:...` and `--ack-managed-msi-delivery-install`. It creates a
separate key, permanent intent and public manager offer, never starts a listener.
Host key/access creation still requires separate real-world authorization.

After the endpoint's separately approved create-only setup emits its public
registration, run `finalize` with the same protected configuration/device inputs
and `--registration-file`, review the exact plan, then explicitly apply. This
creates the fresh enrollment metadata, protected empty spool and new manager/LAN
configuration, with a completion receipt. It does not alter the original LAN
configuration. Starting with the staged `windowsManagedMSIConfigFile` is a
separate activation step. Partial setup permanently fences reuse; there is no
repair, deletion, adoption or reset command.

The setup, startup and transactions reject purpose-key reuse across enrollment,
TLS, prepared MSI, WUA, service and Linux package authority. Native import and
execution use the prepared package's bounded x64/machine/embedded-cabinet review
and outcome vocabulary, under fresh managed signatures, keys and ledgers.

## Required remaining acceptance

Native Windows acceptance remains pending: approved disposable x64 machine,
real exact-package review, NTFS ACL/reparse/hardlink/replacement custody, protected
service/IPC process identity, LocalSystem token/network-risk confirmation,
transfer interruption and resumed prefixes, current-leaf renewal/revocation
races, imported-byte/native-metadata mismatch, late/expired approval, crashes
around claim/attempt/result writes and 0/3010/1641/1618/unknown-result behavior.
Source Node/Go fixtures, static checks and cross-builds do not establish these
host outcomes or authorize an actual MSI upload, service grant or installation.
