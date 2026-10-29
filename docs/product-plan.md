# Product scope

Tracebolt is a self-hosted tool for understanding and administering machines in
one environment. A Linux manager and shared dashboard combine native inventory,
resource history, logs and explicit diagnostic workflows. It is a development
pilot, not a production-readiness promise.

For implemented functionality and setup, use the [project overview](../README.md)
and [guides](README.md). Current work is ordered in the
[Windows](windows-admin-roadmap.md) and [Linux](roadmap.md) priorities.

## Current delivery goal

The product direction is a locally operated network assistant: a manager and
local model should help find and explain problems, and eventually execute
administrator-delegated repairs on selected devices. The requested long-term
authority includes general administrative commands; it is not limited to the
currently implemented named service and package actions. This is a target,
not a description of an available autonomous agent or a grant to any host.

Existing work continues to prioritize dependable Windows Admin data and native
acceptance before a new release.
Target a fresh clean installation; there is no existing-user migration rollout.
Linux remains the manager platform and the established endpoint development path.
Windows and Linux capabilities have different source and permission boundaries;
macOS currently has only a limited standalone collector.

## Interface

- Compact, readable administration screens, English by default with German available
- Searchable/paged inventory and direct access to useful device, service and log context
- Original observation time, coverage and unavailable/partial/stale states beside data
- Short labels and optional detail rather than repeated technical disclaimers
- Useful real UI screenshots, clearly labeled when they use invented data

## Evidence and collection

Use fixed native sources with typed, bounded capabilities instead of arbitrary
scripts. Keep facts, hypotheses, missing evidence and suggested next steps
separate. Empty data never proves that a machine is healthy, protected or patched.
Identity must not rely on a hostname, IP address or hardware serial.

Use Linux native interfaces/package databases/systemd/journald where authorized.
Use selected Windows native APIs, SCM, registry and fixed WMI fields; never
`Win32_Product` queries that can trigger MSI repair. Broader software/user-context
coverage is additional scope, not implied by the current machine inventory.

## Permissions and release boundaries

The main agent stays unprivileged. Broader collection, content reads, privileged
helpers, service/package actions, external notifications and AI providers require
their own exact approval. Current models do not receive shell authority or credentials.
Preserve protected identities, TLS, revocation, replay defenses and consumed state.

Future autonomous general administration needs a separately designed and locally
approved delegation: exact devices and authority, protected execution credentials,
bounded runtime and resource use, auditable actions and results, revocation and
an emergency stop. Model inputs and outputs are untrusted; observed content must
not become instructions or independently authorize an operation. Define behavior
for failure, partial execution and uncertain outcomes before connecting a model to
an executor. Granting that capability, deploying a model or changing host rights
requires the relevant explicit approval. Loopback or LAN transport alone does not
prove that a model provider performs inference locally or never forwards data.

Source implementation, released artifacts and native acceptance are distinct.
Record actual OS/architecture/service identity and exercised behavior; fixtures,
screenshots and cross-compilation cannot establish installation or reboot support.
Backup/restore and production hardening remain necessary before broader rollout.

## Deferred

Integrated remote desktop, general file management, multi-customer tenancy/billing
and universal log/database adapters. Autonomous commands and unattended remediation
remain unimplemented targets subject to the delegation and verification gates above.
Windows update installation follows trustworthy read-only evidence and
separate action approval. Narrow service and selected Linux package source work
does not imply blanket management authority.
