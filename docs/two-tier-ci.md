# Focused source checks and complete release validation

Routine pull requests and pushes to `main` use **Focused source checks**. They
always build and vet all Linux Go source, cross-build all Windows/amd64 source,
and type-check/build the entire UI. Compilation is not native acceptance.

The source selector compares the exact checked-out commit (including a PR merge
commit) with the PR base or push-before SHA. It reads Linux and Windows Go package
metadata, merges runtime, internal-test and external-test import edges, and follows
reverse dependencies transitively. Test files and Go embed inputs select their
owning packages. Only Linux-runnable packages execute here; Windows-only source
still receives the whole Windows build and its Linux-runnable dependents are
selected. No test result or package is inferred from a timing weight.

Missing history, deleted/renamed/unrecognized files, dependencies, workflow or
security-contract changes broaden to all Linux non-race source packages. Shared
UI and unmapped UI-affecting changes broaden to all existing browser entry points
and UI interactions. This fallback does **not** invoke the race workflow.
The exact generated `tests/security/go_failure_allowlist.json` is the sole
security-directory exception: only an ordinary modification with unchanged Git
mode 100644, a regular no-follow checkout file, and byte-for-byte equality to a
fresh canonical derivation of every current Go source byte and test root qualifies.
Invalid, missing, deleted, type/mode-changed or forged data keeps broad selection;
the existing runtime allowlist guard still applies. Actual Go edits still select
their dependency closure, and reporter/generator/selector or shared-file changes
still broaden normally.

Ordinary recognized API/UI changes select their dependent packages and existing
browser flows. Vite's actual dependency graph selects related UI tests. New
unknown features broaden until an explicit reviewed flow mapping exists.

Ten exact existing regression roots always run: named authorization/revocation,
certificate/activation admission, durable telemetry replay, claim rollback,
missing Windows event authority, Linux/Windows mutation fences, journal durability,
and Windows used-state loss. A missing, duplicate or skipped critical root fails.
Selected Go packages otherwise run their ordinary non-race tests, excluding only
the two existing dedicated dense/guided roots retained in full validation.

Six existing login/bootstrap/password/logout/expiry/interrupted-logout browser
cases always run via the explicit `--pr-smoke` selection. Their exact positive
completion is required, and they use distinct PR-only result names. The default
LAN browser invocation still runs every existing case. Domain-specific entry
points use their existing fixture setup, exact screenshot checks and completion
reports; existing standalone browser evidence validators are reused. Reduced
checks cannot supply a complete browser or native-acceptance claim.

Raw Go JSONL/stderr and UI runtime output remain private temporary files. Failed
Go checks use the existing source-allowlisted finite diagnostic projection; UI
and browser output identifies the fixed stage/flow. Successful selected public-safe
screenshots and existing normalized reports are retained for three days in
`focused-ui-review-<sha>`. No raw traces, manager logs, credentials or real telemetry
are uploaded, and these artifacts are never release proof.

## Full and release gates

The **Validate** workflow keeps its path, job names, all race packages and roots,
dense matrix, native/runtime checks, full UI/browser suite, artifact retry,
source/run/attempt bindings and exact aggregate evidence. It now runs on manual
dispatch or nightly at 02:17 UTC, not on every PR or merge. The fixed public Debian
feed compatibility check also runs in these full invocations. Native installation
and Setup acceptance workflows remain separately owner-dispatched with their
existing approvals; this change never calls or schedules them.

All three release workflows require `full_validation_run_id`. Before candidate
build/verification and again before publication, a read-only preflight requires:

- the explicitly named full Validate run, never a search for the latest run;
- the exact released source SHA on `main` in this repository;
- a completed successful run and unchanged current attempt;
- every expected full job exactly once, successful, with the exact source/attempt;
- all exact-race aggregate verification steps completed successfully.

Focused PR checks, a PR merge SHA, skipped/failed/missing/duplicate jobs, foreign
repositories, stale attempts, and the publisher SHA substituted for the Windows
accepted source SHA all fail this gate. Windows' accepted source tree and exact
manual native-proof verification remain independent and unchanged. The preflight
has read-only Actions access; it cannot dispatch a workflow or publish anything.
Full source evidence is actor-independent: a maintainer or bot may legitimately
trigger read-only tests of the same exact repository/main source. This establishes
source-test completion only. It never substitutes for the unchanged owner/actor,
manual-consent and native/publication authorization checks.

For a release, manually run full Validate on the exact source or wait for its
nightly run, then supply that successful run ID together with the existing release
and native acceptance inputs. A new source commit requires matching new evidence.

## Checks and rollout

The focused aggregate is **PR build and affected-flow checks**. It runs even when
its prerequisites fail and rejects missing, skipped, cancelled or failed selection,
Go, UI or browser jobs. The old full aggregate name **Go tests and build-only
platform checks** retains its full meaning and is not reused for reduced coverage.
Any external required-check policy must be reviewed for these distinct names;
this source change does not edit branch protection or repository settings. A
read-only observation on 2026-10-12 found no enforced main branch protection/check
contexts or rulesets; that is not a guarantee about future configuration.

There is no promised runtime target. Shared/unknown changes intentionally cost
more, and affected-package tests can still be substantial. Measure the first
hosted focused run before claiming a speed improvement. Full suites, live browser
runs and native acceptance were not executed as part of this source-only redesign;
local validation is limited to inert selection/report/workflow contracts.
