# Fixed enrollment issuer

`internal/enrollmentissuer` is the isolated signing component for the proposed
enrollment v2 backend. It is not a production provisioning command, an approval
registry, an installer, a service, or evidence of deployed enrollment. The
published v1 manager/sender interfaces are unchanged.

## Public interface

```go
func New(
    issuerDER, rootDER []byte,
    signer crypto.Signer,
    expectedIssuerFingerprint string,
    now time.Time,
) (*Issuer, error)

func (*Issuer) Sign(
    ctx context.Context,
    intent enrollmentcrypto.Intent,
    now time.Time,
) (enrollmentcrypto.VerifiedCertificate, error)

func (*Issuer) Fingerprint() string
func (*Issuer) IssuerDER() []byte
func (*Issuer) RootDER() []byte
```

Although the constructor's argument is `crypto.Signer`, the first implementation
accepts only a concrete, preprovided `ed25519.PrivateKey`. Arbitrary wrappers,
remote signers and HSM providers are rejected without invoking them. An external
signer needs a separately reviewed deterministic/idempotent recovery contract.
The interface exposes no generic signing operation or private-key export.

The public DER inputs and accepted private key are copied. Returned public DER
accessors are defensive copies. The handle's pointer and dereferenced value have
redacted formatting, JSON, text and structured-log representations. Copies of the
handle share immutable private state and support concurrent signing.

## Preprovided authority and custody boundary

Supply exactly two public certificates: a dedicated, client-only Ed25519 issuing
intermediate and its direct, self-signed root. Supply only the intermediate's
private key. There is no parameter for an offline root private key, and no
filesystem loading, random-key generation, network access, trust installation,
ambient root lookup, missing-chain retrieval, or clock lookup in this package.

The constructor verifies:

- The exact lowercase SHA256 fingerprint of the intermediate matches trusted
  instance configuration, not a request-supplied fingerprint.
- The intermediate is an X.509 CA with explicit path length zero and exclusively
  client-auth EKU. Its key usage is certificate signing with optional CRL signing,
  with no endpoint role or other key usage.
- Its Ed25519 public key passes the shared `internal/keyvalidation` policy. The
  private key's public component matches and a local, fixed domain-separated
  possession check detects malformed private keys with inconsistent public
  suffixes. This proof is never returned.
- The root is distinct in both DER and public key, self-signed, a valid CA, and
  permits at least one intermediate. The root may use the existing LAN trust
  policy's Ed25519, RSA >= 2048, or P-256/P-384/P-521 ECDSA keys and modern
  supported certificate signature algorithms.
- Both certificates are currently valid, the issuer's validity lies within the
  root's, issuer subject/authority linkage and signatures match, unknown critical
  extensions are rejected, and standard X.509 client-auth verification produces
  exactly the supplied intermediate followed by the supplied root.

The root being accepted as explicit trust does not waive its signature, time,
key-strength, key-usage or path-length checks. In particular, a root with path
length zero is rejected even though a generic chain verifier can treat an
intermediate being verified as its target certificate.

The caller must securely load and provision the dedicated private material, with
the ownership, private permissions, symlink/hardlink protections, separate
runtime identity, secret delivery, backup and compromise recovery required by
the deployment design. An in-memory component cannot attest file protections or
prove that a key has never been reused elsewhere. Passing valid certificates
does not authorize a real trust change, deployment or credential provisioning.

## Fixed leaf policy

`Sign` takes a complete server-owned `enrollmentcrypto.Intent`. It first applies
`ValidateIntent`, checks the exact configured issuer fingerprint, revalidates the
provided authority at the supplied time, and bounds the leaf by the issuer's
validity. It accepts no CSR or caller-supplied certificate template.

The sole leaf template has:

- The recorded server-assigned device ID as its only subject field/CN
- The recorded canonical Ed25519 public key and positive 128-bit-bounded serial
- Exact recorded second-resolution start/end times, at most 30 days apart
- Non-CA basic constraints, digital-signature key usage, exclusive client-auth
  EKU, Ed25519 signature, and the intermediate's authority key identifier
- No SAN, arbitrary extension, CSR subject, requested privilege, CA delegation,
  policy, URL, or automatically selected serial/time

The result is independently checked through `enrollmentcrypto.VerifyIssued`
before return. That also preserves the existing HTTP-test leaf-only encoded
certificate header limit. The store still owns transport-domain separation; an
HTTP-test issuer must not be reused for a TLS production instance.

## Crash recovery and authorization

The caller must perform these operations in order:

1. Authenticate the operator approval and durably bind the device/key.
2. Allocate a unique serial and immutable complete intent, recheck lifecycle
   authority, and commit that intent before invoking `Sign`.
3. Sign the already recorded intent with the pinned intermediate.
4. Recheck the current lifecycle/revision/terminal state and atomically commit
   the matching verified DER. If a cancellation, revocation, expiration or
   competing transition wins, discard the local result.
5. Deliver only the already committed DER through the store's authorized,
   idempotent credential-delivery operation. Recheck approval and revocation at
   activation and every telemetry commit.

This signer keeps no issuance ledger, does not enforce serial uniqueness, and
cannot independently determine that an intent was approved or persisted. A
`VerifiedCertificate` proves the cryptographic/template contract only. It is
never sufficient approval, activation, delivery or telemetry authority.

The standard-library pure Ed25519 signer and explicit fixed serial/template need
no entropy. An internal reader rejects any accidental request for signing
entropy. Repeating the same valid intent with the same preprovided material
produces byte-identical DER, including after process reconstruction. Advancing
the supplied time within the valid interval does not change the template. A
crash after signing but before commit can therefore retry the exact persisted
intent without creating a different credential. The store must not replace the
serial, key, identity, issuer, template or validity during that retry.

Context cancellation is checked before signing, after signing, and before
return. A running standard-library operation is not interruptible, but a result
is discarded when cancellation is observed. All errors and diagnostics are
fixed/redacted; input material and signing errors are not interpolated.

The deterministic retry contract is scoped to this fixed template and the pinned
Go toolchain. A future template/toolchain/issuer transition must preserve delivery
of already committed DER and explicitly review uncommitted-intent recovery.

## Ephemeral verification

Run with the repository toolchain:

```sh
go test ./internal/enrollmentissuer
go test -race ./internal/enrollmentissuer
go vet ./internal/enrollmentissuer
```

Tests use ordinary generated ephemeral keys only, including supported root-key
compatibility. They cover fixed leaves, client-only chain verification, wrong
roles/chain/fingerprint/key/validity, cancellation, zero handles, defensive
copies, concurrent copied handles, and pointer/value diagnostics. A fresh test
process receives only ephemeral fixture material over private stdin and must
produce identical certificate DER; no private material is put into argv,
environment variables, fixture files or test output. Tests do not exercise a
live credential, a deployed endpoint, system trust, installation or v1
low-order-key forged-request reachability.
