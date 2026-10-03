# Edwards25519 key validation dependency

The defensive key validator pins `filippo.io/edwards25519 v1.2.0` from the public Go module registry. It uses the upstream-derived point decoder, canonical encoding, cofactor multiplication and scalar multiplication; signature verification remains in Go's `crypto/ed25519`.

The policy requires a canonical, nonidentity, prime-order public key. Checking only the encoded length or merely eliminating pure small-order points is insufficient for this stricter trust boundary. Standard generated Ed25519 keys continue to pass. Tests here use ordinary generated keys and pure point-classification contracts; they do not establish exploit reachability through existing certificate/HTTP surfaces.

- [Versioned package documentation](https://pkg.go.dev/filippo.io/edwards25519@v1.2.0)
- [Pinned upstream source](https://github.com/FiloSottile/edwards25519/tree/v1.2.0)
- [Required BSD-3-Clause notice](edwards25519-LICENSE.txt)

Module checksum: `h1:crnVqOiS4jqYleHd9vaKZ+HKtHfllngJIiOpNpoJsjo=`.

Include the dependency notice with relevant binary/container distribution materials. This file covers the added dependency, not an exhaustive project-wide attribution audit or a change to Tracebolt's own licensing choice.
