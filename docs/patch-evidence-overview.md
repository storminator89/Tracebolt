# Read-only patch evidence overview

The device page's **Patch evidence** tab gives authenticated LAN operators a
compact, source-labelled review of existing Linux or Windows observations.
It is a source feature, not a current patch-compliance/security assessment or
native/release acceptance. Synthetic, unknown-platform and macOS devices do not
gain Linux or Windows patch scope.

## Linux

The overview reads only the existing metadata endpoint for the separately
consented [complete cached APT candidate generation](complete-cached-updates-extension.md).
It does not request candidate rows, query installed packages, refresh APT or open
a package-action workflow. There is no fallback to the separately consented
bounded preview. If complete-generation data is absent, its counts remain unknown.

An eligible generation shows its original capture, known candidates, held
candidates, unknown comparisons, compared/installed counts, and original oldest
index modification time and age at capture. Capture age and package-index age
remain distinct. Index timestamps cannot prove a successful repository refresh;
metadata younger than 48 hours still has unknown source freshness. Completion
means all declared known rows arrived, not that every package was comparable or
that the device is fully patched. Candidate installation, dependencies, phased
rollout, CVEs and reboot needs remain unchecked.

Newer failed capture attempts and transfer states keep their own original times.
They never replace or refresh an earlier complete capture. A pending transfer
becomes expired at its original deadline even without a metadata refresh. The
original 24-hour generation limit still hides candidate counts. Refresh reads
the manager only, and does not reset capture or cache age.

## Windows

The overview reuses the existing admitted Windows inventory resource; opening
the tab does not start a second reader. Two separate cards summarize:

- [Offline cached WUA results](windows-update-inspection.md): original capture,
  quality, observed-count exactness/lower bound, retained row count, unknown cache
  freshness, method and scope limits. Installed, hidden and driver updates are
  excluded; zero results is not proof of patch coverage.
- [Patch context](windows-patch-context.md): original capture, reported
  build/revision, retained-event count, method/partial-read coverage and checked
  reboot indicators. A successful empty history does not claim a QueryHistory
  read. Partial results without retained rows do not claim a successful row read.
  Retained installation/removal events are not current installed-update inventory.
  Unknown indicators never become reboot clearance or an urgent reboot verdict.

Totals are not combined. A denied or unavailable latest source is not replaced
with an older successful retained source in the overview. Earlier captures remain
available only through their existing, explicitly labelled source-view disclosure.
Future, expired, invalid, revoked or session-ended projections retain their
existing hiding rules and cannot become successful zero-count observations.

## Source navigation and boundaries

**Open source view** deliberately opens the selected device's existing
Inventory → Updates view: complete APT candidates on Linux, cached WUA/patch
context on Windows. Existing source views, setup guides, independent local grants
and separately reviewed action controls remain authoritative. The overview
neither prepares nor approves a plan, creates a job, issues a permit, scans,
installs, accepts update terms, reboots or exports data.

No API, wire, ledger, consent, collection, authority, CI/workflow, host or security
configuration changes are introduced. The existing English/German controls and
keyboard-accessible device tabs are reused. Verification uses invented source
and DOM fixtures, including original-age expiry, unknown/partial counts,
late-response cancellation, no-row-query entry and deliberate source navigation.
No manual browser or native acceptance is claimed.
