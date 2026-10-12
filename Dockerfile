# syntax=docker/dockerfile:1
# No credentials, private configuration or runtime database enters this build.
ARG NODE_VERSION=24
ARG GO_VERSION=1.27.1
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
# TypeScript checks the shared, entirely synthetic Go/UI contract fixture.
COPY internal/api/testdata/complete-overview-synthetic.json /src/internal/api/testdata/complete-overview-synthetic.json
# Keep the shared synthetic Windows patch-context contract available to TypeScript.
COPY internal/windowspatchcontext/testdata/snapshot.json /src/internal/windowspatchcontext/testdata/snapshot.json
COPY internal/windowssecurity/testdata/snapshot.json /src/internal/windowssecurity/testdata/snapshot.json
COPY internal/windowssessions/testdata/snapshot.json /src/internal/windowssessions/testdata/snapshot.json
# Preserve the Go-to-TypeScript Windows contact wire contract during typecheck.
COPY tests/fixtures/windows-contact-view.json /src/tests/fixtures/windows-contact-view.json
COPY tests/fixtures/windows-capacity-view.json /src/tests/fixtures/windows-capacity-view.json
COPY tests/fixtures/windows-resource-view.json /src/tests/fixtures/windows-resource-view.json
COPY tests/fixtures/windows-maintenance-view.json /src/tests/fixtures/windows-maintenance-view.json
COPY tests/fixtures/windows-service-health-view.json /src/tests/fixtures/windows-service-health-view.json
# Exact synthetic selected Windows action operator output used by TypeScript.
COPY tests/fixtures/windows-service-action-view.json /src/tests/fixtures/windows-service-action-view.json
COPY tests/fixtures/windows-service-action-history.json /src/tests/fixtures/windows-service-action-history.json
# Exact synthetic Windows incident inbox projection used by TypeScript.
COPY tests/fixtures/windows-incident-inbox-view.json /src/tests/fixtures/windows-incident-inbox-view.json
# Shared proactive identity contract and its TypeScript declaration; no test runner.
COPY tests/e2e-review/proactive-ai-browser.mjs tests/e2e-review/proactive-ai-browser.d.mts /src/tests/e2e-review/
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/manager ./cmd/lan-manager \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/action-setup ./cmd/action-setup \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/windows-action-manager-setup ./cmd/windows-action-manager-setup \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/windows-update-manager-setup ./cmd/windows-update-manager-setup \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/windows-software-manager-setup ./cmd/windows-software-manager-setup \
    && mkdir -p /out/data/state /out/run/tracebolt \
    && chmod 0700 /out/data /out/data/state \
    && chown -R 65532:65532 /out/data

# A static Go executable needs no shell, package manager or root account.
FROM scratch AS runtime
COPY --from=build /out/manager /tracebolt/manager
COPY --from=build /out/action-setup /tracebolt/action-setup
COPY --from=build /out/windows-action-manager-setup /tracebolt/windows-action-manager-setup
COPY --from=build /out/windows-update-manager-setup /tracebolt/windows-update-manager-setup
COPY --from=build /out/windows-software-manager-setup /tracebolt/windows-software-manager-setup
# Preserve the project license and pinned dependency notice in the distribution.
COPY --chmod=0444 LICENSE /tracebolt/licenses/LICENSE
COPY --chmod=0444 docs/dependencies/edwards25519-LICENSE.txt /tracebolt/licenses/edwards25519-LICENSE.txt
# Public system roots support optional outbound HTTPS integrations; agent trust
# still uses only its explicitly configured private CA pool.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=web /src/web/dist /tracebolt/web
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/run /run
USER 65532:65532
WORKDIR /tracebolt
EXPOSE 8443 8444
ENTRYPOINT ["/tracebolt/manager"]
# Safe failure when LAN credentials/configuration have not been supplied.
CMD ["--lan-config", "/run/tracebolt/lan.json"]
