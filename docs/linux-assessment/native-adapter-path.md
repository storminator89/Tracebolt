# Next Linux software/update observation adapter

Status: original next-step plan. Exact release/source-package observations are
now implemented in the separate managed-operations-v2 candidate; see
package-contract.md and http-contract.md. Cached APT and the catalog-matching
bridge remain separate work. The earlier operational/offline archives are unchanged.

## Smallest useful extension

1. Add a new explicitly versioned Linux snapshot/wire shape for selected fields
   from `/etc/os-release`: exact ID, VERSION_ID and VERSION_CODENAME. Do not use
   display text or ID_LIKE to infer Debian/Ubuntu applicability. Preserve source
   time, availability/reason and the agent-visible namespace limitation.
2. Preserve dpkg Package/Version/Architecture plus the Source package/version
   already supported by the isolated assessment parser. Distinguish an explicit
   Source field from the documented default when the actual Source field is
   absent. Existing four-field operational rows do not establish either mapping.
3. Keep installed-artifact/repository origin unverified unless a separate reviewed
   adapter justifies it. An enrolled key authenticates report bytes, not vendor
   provenance or an uncompromised endpoint. No JSON boolean or uploaded catalog
   can declare that verification into existence.
4. Add a separate bounded, read-only cached APT candidate adapter. Its results
   mean “listed by the local configured cache,” not downloaded, installable,
   vendor-authenticated, applied or active. Advisory fixed versions never create
   offered-update rows. Missing/stale/partial caches remain explicit.

No privileged APT refresh, package installation, network probe, repository trust
change or external inventory transmission is part of these reads. Commands, if
needed, use fixed trusted executables/argv, a clean environment and bounded output;
package identities must pass the appropriate grammar before becoming arguments.
No shell, descriptions, maintainer data, arbitrary file lists or repository URLs
are exported. Configured local mirrors and private sources need privacy-preserving
labels and must not be silently called official vendor provenance.

## Wire and lifecycle gate before implementation

The design must specify exact new fields, count/byte limits, per-field privacy,
unsupported/missing states, source ages and profile-consent compatibility. It must
retain legacy frame decoding and exact pending-byte retries. A sender with a
pending old frame must not silently rewrite it or reset sequence state. Manager
and agent version compatibility and upgrade order must be explicit. A new field
must never retroactively change the meaning of stored v1 data.

The current managed profile already names installed software, but that does not
authorize silently adding unrelated identifier, configuration-file or trust-store
content. Only the reviewed source/release mapping fields should be proposed for
this extension. If scope materially grows, fresh consent/binding is required.

## Initial platform matrix

- Debian 13 / Trixie: source-package mapping can feed the existing matcher once
  exact release and source facts are present. An unsigned operator upload and
  unverified installed origin yield review candidates/unknown coverage, not
  confirmed affected/fixed/not-affected assertions.
- Ubuntu 24.04 / Noble: installed inventory and cached APT candidates can have their
  own read-only acceptance. They must not be evaluated with Debian vendor rules.
  Ubuntu CVE coverage remains unknown until its vendor-specific adapter, semantics
  and corpus are reviewed.
- Other releases/distributions, containers and altered namespaces: explicit
  unsupported/partial states. Never use version suffix resemblance as authority.

## Required ordinary fixture corpus

- Exact supported IDs/releases versus derivatives, absent/duplicate/invalid
  os-release fields, quoted values and inconsistent codename/version pairs.
- dpkg explicit/default Source semantics, epoch/tilde/binNMU versions, foreign
  architectures, residual/incomplete records and ambiguous/malformed records.
- Cached candidate old/equal/new versions, missing candidate/index, mixed
  architectures, pinning/held state, partial selection, stale/future cache times
  and unavailable tools. No update offer from an advisory threshold alone.
- Unknown artifact origin and unverified catalog must remain unknown/candidate;
  no matches in a partial scope cannot produce a global zero-vulnerability claim.
- Legacy/new wire coexistence, tampered extra fields, exact retry across restart,
  preserved sequence and consent binding, revoked identity and quota rollback.
- Actual nonprivileged Debian/Ubuntu runtime reads on an explicitly authorized
  disposable environment, with pass/fail/count-only artifacts. The current cloud
  sandbox lacks its dpkg status database, so it cannot establish positive native
  package/update coverage. No host/service/trust changes are implied by this plan.
