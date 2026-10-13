# Fresh reusable cached Windows update jobs

Source candidate only. The source fixtures and cross-builds do not authorize
Windows setup, credential generation, ACL/SCM changes, native WUA installation,
activation, migration or release. No host operation is part of these checks.

## Fresh explicit setup

This is a separate create-only option for the paired background MSI/cached-WUA
profile. Consent `tracebolt.windows-selected-update-consent.v6` explicitly binds
background execution, coordinated mutation and reusable update jobs. The local
background provision plan is v3, the paired review plan is v7, and the shared
fence, plan, roster and activation are v4. Each exact participant digest still
pins the entire independent grant or consent, separate public keys, original
identity and fixed expiry. Existing versions retain their original byte shapes,
32-update lifetime limit and activation rules; none can be adopted or promoted.

Use the reviewed offers and matching source-built artifacts from the
[paired background setup](windows-background-cached-updates.md). Add
`--background-updates --reusable-update-jobs` to read-only review and apply.
Apply requires the exact new combined digest, all existing paired/background
acknowledgements and the separately unchecked
`--acknowledge-reusable-update-jobs`. Reusable MSI remains required and retains
its separate `--acknowledge-reusable-managed-jobs` acknowledgement. Read-only
review rejects acknowledgements. The standalone selected-update command cannot
select this profile.

Optional WUA scheduling remains independently selected with
`--allow-scheduled-updates` and separately acknowledged on apply with
`--acknowledge-scheduled-updates`. The v6 consent's scope/acknowledgement pair is
absent unless selected. Optional scheduled MSI likewise retains its own reviewed
offer and separate selection/acknowledgement. Every combination is pinned by the
new exact plan digest. Reusable jobs alone confer no scheduling permission.

The existing background registration, public service configuration, relay and
manager-signed registration wrappers continue to bind their complete nested
consent and immutable v4 roster. Old registration or activation signatures do not
authorize a new participant. Both dedicated services remain disabled and the
observer stays stopped after setup. Finalizing registrations, starting the
observer and activating either service remain separately approved operations.
There is no setup execution or new observer privilege implied by this source.

## Explicit successful-result retirement

Each exact cached GUID/revision still requires its own fresh readiness, review
and named installation approval. No earlier update approval, retirement, saved
history, scheduler or MSI result authorizes another update. Original cached-only,
no-download, no-EULA-acceptance, no-reboot and one-attempt native rules remain.

The new profile can replace bounded current job evidence only after an explicit
retirement bound to the exact successfully settled result. Native return,
successful cleanup, durable result/report and exact released shared-owner receipt
are all required. Failed, partial, unknown, not-attempted or unresolved results
cannot retire. Neither elapsed time, reboot, service exit nor a missing process
establishes completion. Retirement never reconstructs a native capability or
retries installation.

The shared fence accepts retirement only while idle and only for the exact
released WUA owner. It advances a permanent WUA sequence floor and a chained
exact-owner digest, then compacts that owner alone. The latest exact retirement
receipt digest is retained for idempotent crash reconciliation; a changed receipt
or older retired sequence is rejected. Owners at or below the retired floor can
never reserve again. MSI retirement keeps its separate sequence floor and chain,
and reusable/scheduled MSI remains supported on the fresh v4 roster. There is no
generic pruning, missing-state repair or remote unlock.

Endpoint retirement persists its exact pending intent before compacting the
shared owner, then records signed retirement acknowledgement and compact history.
If a response is lost, only those exact saved bytes may reconcile; a restart
cannot repeat native work or mint a refreshed outcome. Missing, contradictory or
uncertain persistence blocks further work. Compact history and retired floors
retain replay evidence after bounded full evidence is replaced.

Retirement never renews the original consent, immutable endpoint identity,
approving leaf, update selection or absolute expiry. Every later job needs fresh
independent authority under the still-valid original grant. Existing scheduled
window, actor, cancellation and no-retry boundaries remain unchanged.

## Bounded manager, executor and relay evidence

Manual approval and prospective schedule reservation each consume a monotonically
increasing job occurrence, independently of readiness sequences. Only one
unretired occurrence is admitted. A canceled, expired or blocked schedule keeps
that occurrence and blocks replacement in this first success-only slice; it is
never silently refunded. An expired, failed, uncertain or not-attempted install
likewise cannot retire. This deliberately does not promise replacement after
every outcome.

The manager must already have accepted the exact original signed successful
result. Result reports keep their original completion time and at-most-300-second
expiry. A previously accepted result can be reviewed later while the original
grant remains valid; a missed or expired unaccepted result cannot be revived or
re-signed to enable retirement. Retirement has its own at-most-300-second fixed
permit and signed acknowledgement. An expired or lost acknowledgement remains
blocked; refreshing status does not renew it.

The manager retains the current complete job and eight compact retired summaries.
The endpoint retains one current attempt and eight compact summaries with saved
signed acknowledgements. Both retain a permanent occurrence floor and chained
retirement evidence, including the chain base needed to validate the retained
window after reopening. Shared-fence retirement separately retains its durable
WUA floor and exact latest receipt. No retained-count value becomes a new lifetime
allowance, and the fixed 512 KiB domain and 128 KiB shared-fence limits remain.

`POST /api/devices/{id}/windows-update-jobs/retire` requires explicit unchecked
review acknowledgement plus the exact job ID, decimal-string occurrence, install
envelope digest and signed-result digest. Existing named install capability,
Origin, CSRF, session, identity and final current-leaf checks apply. The compact
Updates view exposes retirement available, pending, retired or blocked alongside
the unchanged result/HRESULT/reboot truth and original grant expiry. Reopening or
an uncertain write uses GET reconciliation; it never automatically approves a
new job. Legacy profiles retain their actual `/32` capacity display.

The observer claims only the exact original retirement permit through
`/v1/windows-update-jobs/retire-claim`. Exact metadata claim replay is allowed
within its original deadline, with final actor and expiry checks after blocking
reads. The endpoint durably reconciles the same intent without recreating install
authority. Its outbox advertises only the latest retirement acknowledgement, and
the manager accepts an identical retained acknowledgement idempotently even after
advancing to a later request. Retirement reconciliation therefore cannot starve
new readiness work or expose old install evidence as fresh authority.

## Native acceptance still pending

A separately approved disposable Windows x64 non-domain-controller gate must
verify fresh setup refusal for missing acknowledgements and old/mixed versions;
disabled staging and exact registration activation; protected-state/observer
ACL separation; successful result and released-owner retirement; repeated
independent jobs and restarts beyond the former lifetime quota; MSI/WUA exclusion
at the actual native edge; failed/partial/cleanup-uncertain denial; and interruptions
before/after fence compaction and before signed acknowledgement persistence.

Fixtures exercise only inert source behavior. They do not establish WUA health,
real NTFS/SCM durability, host grants, native update acceptance or release.

## Optional fresh manual-download coexistence

The separate [download coexistence profile](windows-selected-update-downloads.md#fresh-manual-download-and-scheduled-install-coexistence)
adds explicitly acknowledged manual WUA download to a fresh paired setup with
one or both independently selected installation schedulers. Existing profiles
retain their bytes and authority. Download never becomes scheduled, supplies
installation approval, moves a fixed window or unlocks a busy/uncertain owner.
Exact successful download retirement precedes a separate fresh WUA installation
review and approval. Native Windows acceptance remains separately gated.
