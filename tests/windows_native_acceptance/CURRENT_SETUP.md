# Current21 hosted packaged Setup gate (source candidate)

This separate gate targets fresh GitHub-hosted Windows Server 2025 x64 only.
It is executable acceptance source, not a native pass, workflow-dispatch approval,
release authorization, or proof of Windows 11 or real Linux-manager/browser use.
The historical `run_setup_gui.py`, `setupgate`, four-case workflow and historical
reports remain unchanged and cannot satisfy this gate. The release publisher's
historical accepted-tree pin is unchanged and does not accept current artifacts.
The separate current publisher adapter remains disabled with an unset accepted
tree until an actual approved successful run is reviewed and pinned.

## Exact profile and actions

The new manual-only `windows-current-setup-acceptance.yml` requires nine distinct
unchecked approvals, an independently reviewed exact source SHA equal to the
clean workflow checkout, the authenticated repository owner, first run attempt,
and standard hosted Windows x64 jobs. No schedule, push, PR, reusable workflow,
HTTP fallback, alternate host, or approval override is provided.

The three separate fresh-VM cases are install/remove, cancellation during hidden
synthetic invitation entry, and pending enrollment with transport interruption.
Each drives the actual unmodified packaged Setup's visible controls and hidden
console. An unavailable interactive desktop fails blocked; no session or UAC
bypass exists. The controller checks the actual Server2025 product/build (26100)
and update revision, independently rechecks the hashed MachineGuid, exact
source/tree, compiled driver and Setup/service/source-input bytes. MachineGuid
and hostname are descriptive correlation fields, not VM identities: hosted images
can repeat them. Fresh isolation relies on GitHub's standard Windows fresh-VM-per-job
contract, distinct authenticated job and runner registrations, reviewed
one-case-one-upload wiring, and each controller's pre-install checks that the
service and application directories are genuinely absent.

Fresh Setup must show 21 scopes, keep all acknowledgements unchecked, independently
require same-key renewal consent, and clear those choices after Back. Consent v14,
outer receipt12, all twenty ordered original sender-bound grant digests, immutable
anchor, current generation1 manifest and primary v5 used markers are verified.
The fixture creates ordinary seven-day initial TLS credentials and disposable
in-memory authority; it never shortens a lifetime to simulate renewal. No renewal
cutover or multi-day retained-host operation is proved.

The optional sampled-event-message, cached-update inspection, selected-update
relay/executor, action relay/broker and selected-account software roots must stay
absent. Prepared MSI executor/custody/relay, managed MSI service/custody/relay and
the shared mutation-fence roots/images are also checked absent. Reusable v3 uses
the same managed roots. The background WUA service state/image and its separate observer relay must also
stay absent. The three implemented optional SCM services,
`TraceboltWindowsDeployment`, `TraceboltWindowsActionBroker` and
`TraceboltWindowsCachedUpdate`, must have no public service registration, even if
stopped. Protected roots contain public setup
registration/config records; CLI registration export has no fixed file path.
These are read-only absence checks, not optional MSI/WUA/service-control or
user-helper acceptance. No event-history search or historical message request
is exercised. Future optional namespaces require a matching explicit guard change.

## What receiver evidence means

The distinct current fixture uses the production enrollment crypto, v10 capability
contract, strict ordinary-frame validator and four independent generation message
validators. At least two accepted ordinary frames, v16 transport and terminal
observations from all four independent domains are required. Independent sequence,
original capture/expiry, chunk order/full digest and exact retry checks remain.
All expected ordinary provider domains must actually appear before protocol pass.

Reported provider qualities are finite counts, original request/frame hashes and
finite status labels only. Denied, missing, unknown, unsupported, bounded and
explicit source-failed outcomes remain visible; they can establish a successfully
handled protocol result without proving usable or complete provider data. Server
Security Center is unsupported. Software-change history and event history are
verified grants only; their two observation entries remain `not_run`.
`fullAcceptance`, provider completeness, real Linux manager, shared dashboard,
Windows 11, renewal cutover, reboot, signing, ARM64 and optional actions remain
explicitly false. No raw inventory, usernames, serials, paths, event text, keys,
console buffers or screenshots are uploaded.

## Hidden-input failure diagnostics

The current driver keeps the same 40-second prompt deadline and requires the
actual attached console, no-echo mode, and invitation prompt. Before reading it,
the driver distinguishes an exited process or a completed installer failure.
Console attach, input/output open, mode, bounded screen reads, secret-echo checks,
echo-enabled mode, and missing prompt now have finite failure stages. These
observations export no GUI/console content, paths, native error text or secrets.
Completed installer failures additionally retain only allowlisted package code
and service phase/reason labels parsed from the complete fixed public failure
rendering. Unknown, malformed or oversized text keeps the coarse failure label.
A console-attach failure does not prove that the installer reached console
allocation. Existing failed reports remain failures; no production fix or native
pass follows from these diagnostic source changes.

## Retention, correlation and release boundary

The completed case observes the limited LocalService token, cancel-without-change,
receipt-owned stop/delete, held delete-pending and final SCM absence. The exact
original receipt SID is used for stopped/absent protected-store inspection, never
service-account lookup after removal. Every current consent is decoded through
its production decoder and checked against its original receipt digest. Used
sender/generation bytes and enrollment/renewable artifacts are retained and
compared after removal. No files, keys, counters or manager trust are deleted.
Incomplete cases must stay stopped/disabled, cannot be retried or uninstalled,
and retain their exact partial state. VM disposal is required but unverified.

The aggregate job accepts only three canonical current-schema reports from the
same exact source/tree/run and mandatory distinct authenticated GitHub job and
runner registrations. Repeated MachineGuid hashes or hostnames neither establish
nor disprove fresh job isolation. Report-content validation alone cannot accept
an aggregate; missing or mismatched execution proof fails closed. Authenticated
GitHub run, attempt, workflow, jobs and artifact ZIP digests bind each report and
the successful install/remove job's public package. Package PE/source resources,
embedded service bytes, full source-input inventory and all file hashes are
verified again. The exact tested bytes are copied unchanged, never rebuilt, to
`windows-current-setup-native-subset-public-<sha>` with a separately finite
`windows-current-setup-native-subset-evidence-<sha>` linkage artifact.
These are unsigned current source-candidate artifacts only. A later publisher
change needs review of the actual successful native evidence and an exact accepted
source commit/tree; no eligible source tree is invented by this implementation.
Original reports and the tested input package expire after three days. Aggregate
outputs last seven days but never replace originals: publication must finish
while all six original artifacts remain live, with exact IDs/digests reverified.
Missing/expired originals cannot be replaced with a rebuild or same-named upload.

Portable authorization/report/fixture tests and a Windows special-tag cross-build
check source contracts only. They do not establish host operations or native
acceptance. Run no native phase without its separate exact target/source/action
approvals. Missing capabilities or access remain blockers, never a reason to
repair global ACLs, elevate the service, bypass OS warnings or broaden scope.
