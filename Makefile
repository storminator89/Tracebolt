.PHONY: build test web run crosscheck
build:
	go build -buildvcs=false -trimpath -o bin/manager ./cmd/manager
	go build -buildvcs=false -trimpath -o bin/agent ./cmd/agent
	go build -buildvcs=false -trimpath -o bin/dev-agent ./cmd/dev-agent
	go build -buildvcs=false -trimpath -o bin/lan-manager ./cmd/lan-manager
	go build -buildvcs=false -trimpath -o bin/manager-restore-quarantine ./cmd/manager-restore-quarantine
	go build -buildvcs=false -trimpath -o bin/lan-agent ./cmd/lan-agent
	go build -buildvcs=false -trimpath -o bin/enroll-agent ./cmd/enroll-agent
	go build -buildvcs=false -trimpath -o bin/agent-service ./cmd/agent-service
	go build -buildvcs=false -trimpath -o bin/action-setup ./cmd/action-setup
	go build -buildvcs=false -trimpath -o bin/package-manager-init ./cmd/package-manager-init
	go build -buildvcs=false -trimpath -o bin/package-helper ./cmd/package-helper
	go build -buildvcs=false -trimpath -o bin/package-runner ./cmd/package-runner
	go build -buildvcs=false -trimpath -o bin/package-guard ./cmd/package-guard
test:
	go test -race ./...
web:
	cd web && npm ci && npm run build
run: build
	./bin/manager
crosscheck:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -o bin/agent-windows-amd64.exe ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -o bin/agent-darwin-arm64 ./cmd/agent

# Source compilation only. These targets never execute a macOS binary or install.
.PHONY: macos-source
macos-source:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -o bin/enroll-agent-darwin-arm64 ./cmd/enroll-agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -o bin/macos-agent-darwin-arm64 ./cmd/macos-agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -o bin/enroll-agent-darwin-amd64 ./cmd/enroll-agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -o bin/macos-agent-darwin-amd64 ./cmd/macos-agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -o bin/macos-agent-service-darwin-arm64 ./cmd/macos-agent-service
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -o bin/macos-agent-service-darwin-amd64 ./cmd/macos-agent-service
