# Guided-enrollment UI: targeted review

Date: 2026-10-03. Scope: `web/src/enrollment.tsx`,
`enrollment-types.ts` and their component/integration tests. This is source and
component evidence. The new guided workflow still requires the publisher's
immutable-source real-browser gate.

## Confirmed boundaries

- Availability comes from the real enrollment capability response. API failure
  has an unavailable state, with no fixture fallback. Linux is the only offered
  client platform; no installer is invented. The retained-record cap includes
  terminal entries.
- The one-time invitation is masked initially and copied only by an explicit
  user action. It is held in component memory, never application browser storage
  or exports. Closing, navigation, hidden-page/session invalidation and the
  invitation deadline remove it from the view. This is not a claim of secure
  memory erasure or control over a clipboard the user chose to populate.
- Public bootstrap export reconstructs an exact allowlisted schema. Certificate
  fields require certificate-only framing and canonical base64, origins must
  match the canonical contract, and the serialized result is checked against
  the known invitation secret. The UI does not perform X.509 trust validation;
  the native client owns that cryptographic boundary.
- Approval requires a locally deliberate comparison of the full fingerprint and
  context value against the native device. Confirmation is bound to the displayed
  identity/revision/key/code and resets when those change. An old mutation result
  cannot replace a newer revocation or a different manager/key context.
- Uncertain create/action outcomes are not automatically replayed or described
  as rolled back. The user is directed to inspect current state. Lost one-time
  secret delivery requires cancel/recreate, not secret readback.
- A validated server-clock anchor plus elapsed time controls deadline display
  and disables expired approval; client wall-clock time does not grant authority.
  Hiding or suspending the page invalidates the anchor and aborts pending reads;
  restoration requires a new anchor. Unknown or expired time synchronously
  clears the displayed comparison state, including before effects run.
  The server remains the final authorization boundary.
- Returned metadata is rendered as text. HTTP-test mode retains its unencrypted
  warning. Approved/issued/activated identity is not described as an online,
  healthy device or an installed service.

## Review fixes and evidence

Independent export tests exposed acceptance of a normalized origin alias such
as an explicit default port. The helper now rejects those aliases and port zero,
along with skipped PEM prefixes/garbage and extra secret-bearing fields. A
separate regression checks a known secret accidentally placed inside an
otherwise allowed public field.

Deadline review also required a server-time anchor because a durable snapshot
may remain `created` or `claimed_pending` after its deadline until an explicit
terminal transition. The UI now clears an expired displayed token and disables
approval without relying on that terminal transition.

An independent check of the next revision caught a disabled, expired comparison
checkbox remaining visually checked for a render. Approval was already disabled.
The final revision derives checked state synchronously from a known, unexpired
clock; the regression is retained.

Independently executed against the reviewed component source:

- `npm run typecheck`: pass;
- complete component suite: **127/127 pass**;
- `npm run build`: pass;
- five additional export-contract tests in
  `web/src/enrollment-security-review.test.ts`: pass.

Reviewed SHA-256 values:

- immutable eight-file UI v3 manifest: `7c9cdfb45ae993db5c27799eadf0d5382b1b3c7a6477cd7aede083d9515b268a`
- `enrollment.tsx`: `9d361547346679fbe6ad83a5ac146d24be641881653c1b62e8f6a005fe661922`
- `enrollment-types.ts`: `0b4d722e29b14823725c6b9bfe680977689a96db0aa7be358f505685051a55d1`
- independent test file: `f7528010164d32c6f0e382ed8af329e37333fb9b916fd5aa5b6ef3b11a6e4f04`

These checks use synthetic credentials and do not establish a real deployment,
native installation, trusted-TLS browser acceptance or production security.
Later source changes and the combined client/server workflow need their own
matching acceptance evidence.
