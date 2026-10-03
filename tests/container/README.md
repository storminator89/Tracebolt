# Container acceptance smoke

Requirements: native Linux Docker Engine, Go matching `go.mod`, and passwordless
`sudo chown` for the fresh disposable fixture directory only. The runtime itself
runs as UID/GID 65532 with a read-only root filesystem and no capabilities.

```sh
docker build -t tracebolt-manager:ci .
TRACEBOLT_CONTAINER_IMAGE=tracebolt-manager:ci go test -count=1 -v ./tests/container
```

Without the environment variable, the lifecycle test explicitly skips. A passing
ordinary `go test ./...` therefore does not imply Docker acceptance. The small
fixture contract test still validates the fabricated telemetry format.

The independently named TLS and HTTP-test lifecycle tests generate a short-lived CA, server/client leaf certificates and a
random operator password in a temporary directory. These are test fixtures only;
no system trust changes or real endpoint credentials are involved. It creates an
isolated named volume and publishes randomized ports exclusively to 127.0.0.1.
It does not use host networking, privileged containers or a Docker socket mount.

Assertions:

- TLS profile: verified TLS 1.3 and exact operator/ingress public origins
- Explicit HTTP-test profile: Ed25519-signed requests, rejected unsigned input,
  mandatory unencrypted warning, and independent profile-marked auth/state
- Static UI reachable and protected API denied before operator authentication
- Operator login and authenticated HTTPS health
- Mandatory client certificate (TLS) or signature (HTTP test), rejection before approval, accepted API sample
  after exact public leaf-fingerprint approval
- Fabricated bounded telemetry only; no host collector invoked
- Approved identity and original idempotent receipt survive a container restart;
  operator session does not
- Revocation rejects the previously approved client; revocation survives removal
  and recreation of the container using the same volume
- Docker runtime inspection confirms fixed nonroot UID, read-only root,
  dropped capabilities and no-new-privileges

Cleanup removes only the test container, its named volume and its generated
fixture directory. A canceled runner can bypass normal cleanup; disposable CI
runners are recommended. Never run this against a user's state volume. Do not
upload fixture directories, runtime databases, raw request/response bodies,
private material or unsanitized logs as CI artifacts. A manager image archive
built before fixtures are generated contains only source-built runtime assets
and may be retained as the build artifact.

This is server-container acceptance, not native agent installation, real LAN
network acceptance, load testing or production assurance. Run separately on each
native architecture; an arm64 cross-build alone is not an arm64 runtime pass.
