# Recent exact reviewed Windows packages

Source candidate, backed by the existing fresh reusable-v3 MSI registry only.
This is a compact recent-package chooser, not permanent catalogue storage or a
package repository. No new native grant, credential, host action or publisher
verification is established by these source changes or synthetic UI fixtures.

## Bounded choices, one payload

“Recent packages” / “Letzte Pakete” rebuilds from the manager's current complete
review and up to eight retained retired-artifact summaries. Each summary already
contains the exact package selection (hash, size, ProductCode, PackageCode,
version, architecture, name, terms-review digest and review reference), native
acceptance digest, and the original unsigned/unverified publisher review label
and evidence digest. Nothing is guessed from an inventory row or reconstructed
from a display name. Repeated fully identical reviews appear once; a changed
terms, native or publisher reference remains a separate choice. Older choices
can leave this list as the existing bounded history advances.

- **Ready here**: the exact reviewed bytes are the current completed manager
  payload. This describes manager custody only, not endpoint readiness or approval.
- **Upload required**: the slot is retired/empty, or the exact upload is incomplete.
  Selecting the saved review fills only its review metadata and clears any chosen
  local file. The operator must choose the exact MSI; size and SHA-256 are checked
  before the existing bounded upload. No review JSON re-entry is needed.
- **Blocked**: another payload occupies the slot, custody is uncertain, or a local
  write is unconfirmed. Selection never removes a payload or bypasses retirement.

The manager still holds at most one 128 MiB payload. Each configured endpoint
still has its own separate 128 MiB bound. Explicit, exact shared retirement is
required before replacement; assigned unresolved jobs retain their payload and
block cleanup. There are no downloads, arbitrary paths, hidden caches, automatic
cleanup, inventory-to-installer matching, or extra payload slots.

## Same-content occurrences remain distinct

Content-derived artifact identity intentionally repeats when identical reviewed
A is uploaded after B. The monotonic global retired count now pins the exact
shared-custody occurrence. Reusable device projections include
`artifactRetiredCount`; frozen device selections and uncertain-write readbacks
must match it. A→B→A therefore cannot revive an old frozen A selection or display
an older retired A outcome as the new A job.

Reusable global reserve/upload/complete/retire requests carry `retiredCount`.
Reserve also pins `expectedArtifactId`, distinguishing the initially empty slot
from a later retired first occurrence before the count advances.
Reusable delivery carries `artifactRetiredCount`. Review, approval and device
retirement additionally carry the exact existing transfer and job sequence.
The manager checks these references at its mutation boundary. A retired device
job cannot be redelivered inside the same shared artifact occurrence. Signed permits,
reports, original grant expiry, readiness lifetime, retired chains/floors and
consume-once native semantics remain unchanged. Legacy singleton/fleet-v2 bodies
and permissions are not promoted to reusable jobs.

## Reload and review

No review, file, acknowledgement or permission is stored in browser persistence.
Reopening reads the existing server artifact and recent reviews. To reconstruct a
lost browser worklist, manually select currently configured devices, freeze the
selection and open each device to read its existing saved state. The manager's
transfer/job evidence is authoritative; no delivery, approval or installation is
replayed. Former browser checkbox choices and group revision snapshots are not
recoverable from the server, so they are not silently reconstructed or guessed.

Groups still organize device selection only. Every delivery, exact package/terms
review, readiness and installation approval remains per device and initially
unchecked. Selection alone performs no API mutation and no automatic next job.
Publisher review remains operator-supplied unsigned/unverified evidence, never a
verified signer or safety claim.

## Checks and limits

Focused contracts and interaction tests cover full-review distinction, bounded
history, exact-byte re-upload, no-write selection, reload, locale, occurrence
pins, old frozen selection invalidation and uncertain-response isolation. The
existing fleet, reusable and singleton interactions remain regression checks.

`web/scripts/capture-windows-software-catalogue-fixtures.mjs --check` compiles the
real production App and validates synthetic DTOs and GET-only route isolation.
It starts no listener or browser and captures no pixels. The existing hosted-only
fleet-MSI CI driver additionally requires eight exact-source screenshots: ready
and blocked choices, and selected review with upload still disabled without
bytes, each in EN/DE at 1440px and 390px. Existing fleet/reusable captures remain.
No new JSON fixture asset is imported, so Docker COPY/ignore fixtures are unchanged.
Native MSI, protected NTFS custody, SCM and exact-package acceptance remain the
separately authorized [native gate](windows-managed-msi-native-acceptance.md).
