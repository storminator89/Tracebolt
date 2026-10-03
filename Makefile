.PHONY: build test web run crosscheck
build:
	go build -buildvcs=false -trimpath -o bin/manager ./cmd/manager
	go build -buildvcs=false -trimpath -o bin/agent ./cmd/agent
test:
	go test -race ./...
web:
	cd web && npm ci && npm run build
run: build
	./bin/manager
crosscheck:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -o bin/agent-windows-amd64.exe ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -o bin/agent-darwin-arm64 ./cmd/agent
