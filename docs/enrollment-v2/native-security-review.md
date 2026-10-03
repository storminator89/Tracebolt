# Guided native enrollment: targeted review

Date: 2026-10-03. Scope: the Linux `enroll-agent` client, shared bootstrap
transport, private enrollment handoff and guided-v2 sender-state continuity.
This is targeted source, regression and actual-process evidence, using only
disposable generated credentials and loopback fixtures. It is not deployment
approval or an exhaustive security audit.

## Confirmed boundaries

- The operator supplies public bootstrap trust through a trusted local path.
  Exact manager/agent origins, instance, profile, issuer and collection policy
  are checked before network activity. TLS uses explicit roots, normal SAN
  verification, TLS 1.3 and vetted DNS answers pinned for dialing. Redirects,
  ambient proxies, cookies and browser credentials are disabled.
- A locally generated identity, CSR and stable operation IDs are committed in a
  protected, exclusively locked ledger before a claim. The invitation and raw
  invitation-bearing request are never persisted. Hidden terminal input disables
  echo before prompting; arguments, environment variables and stdin do not offer
  alternate secret entry. Diagnostics use opaque, redacted private handles.
- Status and credential retrieval require fresh, purpose-bound possession
  proofs. Received snapshots, complete immutable intent and issued certificate
  must match the local key and claim context. Certificate persistence precedes a
  fresh activation proof. An uncertain activation can reconcile without creating
  another identity.
- Only an exact bounded enrollment error received through authenticated TLS can
  mark a claim definitely rejected and permit correction of a mistaken secret.
  The key, CSR and operation IDs stay unchanged. Any earlier ambiguous candidate
  remains pinned until a matching bound-key snapshot resolves it. Generic,
  malformed and HTTP-test errors cannot authorize correction.
- Key/certificate/CA artifacts precede the one-time durable sender initialization.
  A runnable guided configuration appears only after the bound sender ledger
  exists. Both direct and foreground guided senders require existing state;
  manual-v1 and guided-v2 bindings cannot silently adopt each other's ledgers.
- Resuming enrollment validates the existing sender state under its exclusive
  lock without creating files, resetting sequence/pending data or deleting the
  sender's crash temporary. Missing or incompatible state fails closed before
  enrollment network activity.

## Findings corrected

1. Persisting a mistaken canonical invitation hash could permanently prevent
   entering the correct secret. The scoped authenticated-rejection mechanism
   above allows same-identity correction without treating ambiguity as failure.
2. Replacing a completed handoff's telemetry directory with an empty private
   directory was accepted on enrollment resume. An independent regression
   reproduced the issue. Guided-v2 configuration now requires an already
   initialized, correctly bound ledger, including when the sender is invoked
   directly. Missing paths, locks and sequence files are not recreated.
3. Calling the normal sender open operation during enrollment validation could
   remove sender-owned crash work. A separate read-only validation path now
   preserves that file. The independent byte-preservation regression passes.
4. Invalid formatting verbs could bypass custom formatting on value structs.
   Secret-bearing client and invitation handles now contain only an opaque
   private-state pointer; explicit persistence uses a private codec. No logging
   sink or credential disclosure was observed.

## Independent evidence

- Three public-contract regressions in
  `tests/security/enrollment_client_boundary_test.go`: pass with the race
  detector. They cover trust/prompt ordering, identity and artifact preservation,
  replaced empty sender directories and preservation of sender crash temporaries.
- Final race checks for `internal/enrollmentclient`, `cmd/enroll-agent`,
  `internal/lanclient` and `internal/lanclientstate`: pass. Scoped vet: pass.
- Final actual three-binary check:
  `go test -race ./cmd/lan-manager -run '^TestGuidedThreeBinaryEnrollmentAndForeground$' -count=1 -v`:
  **both TLS and explicit HTTP-test profiles pass**. Production and harness
  Go-source/module hashes were unchanged during the run.
- Each profile starts separate built manager, native enrollment and foreground
  sender processes. The check verifies terminal echo is disabled before feeding
  the synthetic invitation, full local comparison, explicit approval, activation,
  guided-v2 initialized state, two actual Linux reports 15 seconds apart, clean
  stop and revocation. Output contains pass metadata, not raw telemetry or keys.
  The test harness uses the race detector; subprocess binaries are normal builds.

The independently reviewed native regression file has SHA-256
`354a32369401586b15039f13064aba72eccb6bb77b730c1110337d61c262dcae`.

The complete independent `tests/security` suite subsequently passed with the
race detector; its vet check and module checksum verification also passed.
A fresh pinned `govulncheck` v1.8.0 scan of this final Linux/amd64 source using
Go 1.27.1 covered 38 root packages and 11 modules. Production/module hashes
were unchanged during scanning. It found zero reachable-symbol findings and
zero imported-package findings. The required `x/crypto` module retains
[GO-2026-5932 in unused OpenPGP](https://pkg.go.dev/vuln/GO-2026-5932), with no
fixed version listed. This is not a blanket claim of vulnerability absence.

## Limits and remaining gates

The native runtime is Linux-only. Cross-build success does not establish
Windows/macOS enrollment or sender support. No service installation, reboot,
automatic update, renewal, lost-key recovery or identity migration is provided.
The issuer's intermediate key is explicitly provisioned; its root key stays
offline. Fixture material must never be reused for a real deployment.

HTTP-test traffic has neither confidentiality nor authenticated manager/UI
responses. Its explicit warning and acknowledgement remain mandatory. A failed
HTTP-test claim can require operator reconciliation and a new authorized
invitation; silently resetting a local ledger is not a recovery procedure.

Valid older backups with the same binding cannot be identified as historical
rollback by these local ledgers. Interrupted initialization with missing state
fails closed; it is not automatically restarted as fresh. Generic transport
failures are not sufficient evidence of revocation. Same-UID/root compromise,
secure in-memory erasure and exhaustive crash-at-every-write testing are outside
this acceptance.

The immutable combined-source real-browser/CI gate remains separate. Component
tests and Go TLS fixtures do not establish trusted-TLS browser acceptance or a
real LAN deployment. Existing-v1 weak-key exploit reproduction is outside this
review.
