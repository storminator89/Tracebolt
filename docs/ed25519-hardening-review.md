# Defensive Ed25519 key-policy review

Date: 2026-10-03. This review covers the nine-file defensive runtime overlay
recorded by manifest SHA-256
`1130885a7148c4a8fb7fd1b0da087d3d0d70111cf1fac1559e3602977396e348`.
All nine captured files were independently verified against the reviewed source.
Enrollment model code is a separate scope.

## Change and assessment

The shared policy rejects noncanonical, identity and non-prime-order Ed25519
public keys. It uses pinned, upstream-derived `filippo.io/edwards25519` v1.2.0
for point operations; existing Go signature verification is preserved. Source
review confirmed the full cofactor/inverse-cofactor subgroup check rather than
only a small-order exclusion. Upstream explicitly permits noncanonical point
decoding, making the additional encoding roundtrip necessary.
[Versioned upstream API](https://pkg.go.dev/filippo.io/edwards25519@v1.2.0)

The guard is applied to certificate key strength in explicit trust material,
key pairs, agent approval and request-time chain validation, plus signed-HTTP
key acceptance. An additive client TLS `VerifyConnection` check validates key
strength and time on an already verified peer chain. Go's ordinary trusted-CA
and SAN verification remains enabled; the callback neither accepts an
unverified chain nor disables certificate validation.

No source-level blocker was identified in this narrow defensive change.
Normal generated Ed25519 keys remain compatible. Malformed or unusual existing
credentials may now be rejected intentionally; no credential is automatically
replaced or reapproved.

## Evidence and limits

Independently completed:

- pure generated-key and point-classification tests, race detector, three runs;
- ordinary generated-key client/server compatibility over real loopback TLS,
  race detector, three runs;
- source review of the key policy and its certificate/signed-HTTP call sites;
- scoped vet and module checksum verification;
- fresh pinned `govulncheck` v1.8.0 on Linux/amd64 Go 1.27.1, with unchanged
  source/module hashes during the scan.

The advisory scan covered 29 root packages and 11 modules, including the curve
dependency and separately unexposed enrollment packages. There were zero
reachable-symbol and zero imported-package findings. One required-module
advisory remains: [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) concerns
unused `x/crypto/openpgp`; dependency inspection showed only Argon2/blake2b
imports from that module. Do not describe this as a blanket clean audit.

An earlier independent regression exposed a proof-of-possession key-acceptance
edge in new, unexposed enrollment code and motivated this hardening. Exploit
reachability through existing HTTP or TLS authentication surfaces was not
reproduced. The existing agent path also requires a certificate from a
configured trusted issuer and explicit operator approval. These prerequisites
must not be omitted when discussing possible impact.

This evidence is not a full changed-tree execution pass, browser acceptance,
fresh native-platform matrix, deployment, or operational security guarantee.
The independent targeted review above is separate from the later publisher
gate. No real credentials or network exposure were provisioned for this review.

## Subsequent immutable checkpoint

Source `786dbf3a672dd80be9c8ad21f68f3d4abefb16ec` passed
[CI run 37145326437](https://github.com/storminator89/Tracebolt/actions/runs/37145326437).
The independently re-read browser artifacts contain 40/40 general/AI/layout
checks, 6/6 managed-preview checks and 10/10 real HTTP-test-handler checks,
with zero runtime errors. GitHub job/step results also confirm successful
native collector execution on Linux, Windows and macOS, actual Linux manager
and sender binaries, and both disposable Docker profiles. These are distinct
execution scopes; the HTTP browser suite does not establish trusted-TLS browser
acceptance, and the three-OS collectors are not three-OS installed LAN agents.

That published checkpoint contains no enrollment implementation. Its passing
gate must not be attributed to later enrollment durability, delivery or loop
work. It also does not establish the previously unperformed existing-path
weak-key exploit validation.
