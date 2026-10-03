# syntax=docker/dockerfile:1
# No credentials, private configuration or runtime database enters this build.
ARG NODE_VERSION=24
ARG GO_VERSION=1.27.1
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
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
    && mkdir -p /out/data/state /out/run/tracebolt \
    && chmod 0700 /out/data /out/data/state \
    && chown -R 65532:65532 /out/data

# A static Go executable needs no shell, package manager or root account.
FROM scratch AS runtime
COPY --from=build /out/manager /tracebolt/manager
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
