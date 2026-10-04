package main

import (
	"context"
	"errors"
	"localrmm/internal/agentinstall"
	"localrmm/internal/bootstrapfetch"
	"os"
	"path/filepath"
)

var errOnlinePreparation = errors.New("online bootstrap preparation was not completed")

// Only PUBLIC, checksum-verified bootstrap bytes enter this temporary snapshot.
// The existing installer independently verifies that exact file before private
// publication. No secret, executable, shell command or ambient temp path is used.
func prepareOnlineBootstrap(ctx context.Context, r agentinstall.Request, in bootstrapfetch.Request, preflight func(context.Context, agentinstall.Request) error, fetch func(context.Context, bootstrapfetch.Request) ([]byte, error)) (agentinstall.Request, func() error, error) {
	noop := func() error { return nil }
	if !r.Apply || r.Action != agentinstall.Install || r.BootstrapFile != "" || preflight == nil || fetch == nil || in.ExpectedSHA256 != r.BootstrapSHA256 || in.InsecureHTTPTest != r.InsecureHTTPTest {
		return r, noop, errOnlinePreparation
	}
	if preflight(ctx, r) != nil {
		return r, noop, errOnlinePreparation
	}
	raw, err := fetch(ctx, in)
	if err != nil || len(raw) == 0 || len(raw) > bootstrapfetch.MaxBootstrapBytes || ctx.Err() != nil {
		return r, noop, errOnlinePreparation
	}
	dir, err := os.MkdirTemp("/tmp", "tracebolt-public-bootstrap-")
	if err != nil {
		return r, noop, errOnlinePreparation
	}
	path := filepath.Join(dir, "bootstrap.json")
	cleanup := func() error {
		e := os.Remove(path)
		if e != nil && !os.IsNotExist(e) {
			return errOnlinePreparation
		}
		if e = os.Remove(dir); e != nil {
			return errOnlinePreparation
		}
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = cleanup()
		return r, noop, errOnlinePreparation
	}
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
		_ = cleanup()
		return r, noop, errOnlinePreparation
	}
	r.BootstrapFile = path
	return r, cleanup, nil
}
