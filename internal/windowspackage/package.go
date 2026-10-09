// Package windowspackage provisions the fixed fresh Windows package payload.
// It never installs, configures, or starts an SCM service, creates credentials,
// adopts existing objects, repairs ACLs, or deletes even a partial installation.
package windowspackage

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"

	"localrmm/internal/windowsservice"
)

const MaxPayloadBytes = 128 << 20
const MaxBootstrapBytes = 64 << 10
const ManifestSchema = "tracebolt.windows-setup-package.v1"

var ErrPackage = errors.New("Windows package provisioning failed; any created objects are retained")
var ErrUnsupported = errors.New("Windows package provisioning requires Windows")

type packageError struct{ code string }

func (e *packageError) Error() string { return "Windows package: " + e.code }
func (e *packageError) Unwrap() error { return ErrPackage }
func failure(code string) error       { return &packageError{code} }

// Code returns only a finite package diagnostic, never a path or native error.
func Code(err error) string {
	if err == nil {
		return "none"
	}
	if e, ok := err.(*packageError); ok {
		return e.code
	}
	if err == ErrUnsupported {
		return "unsupported-platform"
	}
	return "package-failed"
}

// Result keeps the new protected path chain pinned for the setup coordinator.
// Close releases handles only. It never removes even incomplete objects.
// Retained reports whether a create was attempted (including an uncertain error).
// BootstrapPath is usable only when Provision returns no error.
type Result struct {
	Layout        windowsservice.Layout
	BootstrapPath string
	Retained      bool
	lease         *lease
}
type lease struct {
	once    sync.Once
	session session
	err     error
}

func (r *Result) Close() error {
	if r == nil || r.lease == nil {
		return nil
	}
	r.lease.once.Do(func() { r.lease.err = r.lease.session.Close() })
	return r.lease.err
}

type objectRole uint8

const (
	programFilesApp objectRole = iota
	programDataApp
	setupDirectory
	serviceFile
	bootstrapFile
	manifestFile
)

type session interface {
	Layout() windowsservice.Layout
	BootstrapPath() string
	CheckFresh(context.Context) error
	CreateDirectory(context.Context, objectRole) error
	WriteFile(context.Context, objectRole, []byte) error
	Verify(context.Context) error
	Close() error
}
type openSession func(context.Context) (session, error)

// Preflight makes only read-only checks: fixed KnownFolders, elevation, NTFS,
// pinned no-reparse trusted ancestors, absent app roots, and absent SCM service.
// Provision repeats all checks using its own pinned handles before any create.
func Preflight(ctx context.Context) error { return preflightWith(ctx, nativeSession) }
func preflightWith(ctx context.Context, open openSession) (err error) {
	if cancelled(ctx) {
		return failure("cancelled")
	}
	s, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if e := s.Close(); err == nil {
			err = e
		}
	}()
	return s.CheckFresh(ctx)
}

// Provision creates only the two absent Tracebolt roots, a public service image,
// and an administrator-only windows-setup sibling containing bootstrap/provenance.
// The caller must validate publicBootstrap with enrollmentclient.ParseBootstrap
// before calling. Invitation material must never be passed to this API.
// There is no recovery, overwrite, retry, or implicit grant/start operation.
func Provision(ctx context.Context, payload []byte, manifest Manifest, publicBootstrap []byte) (Result, error) {
	return provisionWith(ctx, payload, manifest, publicBootstrap, runtime.GOARCH, nativeSession)
}
func provisionWith(ctx context.Context, payload []byte, manifest Manifest, bootstrap []byte, architecture string, open openSession) (result Result, err error) {
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	if err = manifest.validateFields(); err != nil {
		return result, err
	}
	if len(payload) < 512 || len(payload) > MaxPayloadBytes {
		return result, failure("payload-size")
	}
	// Snapshot caller-owned bytes before verification and keep exactly that image
	// through create/readback. No hash-to-write alias remains with the caller.
	payload = append([]byte(nil), payload...)
	if err = manifest.Validate(payload); err != nil {
		return result, err
	}
	if manifest.Architecture != architecture {
		return result, failure("architecture-mismatch")
	}
	if len(bootstrap) == 0 || len(bootstrap) > MaxBootstrapBytes {
		return result, failure("bootstrap-size")
	}
	// Retain an immutable in-memory snapshot. The package owns no invitation/key.
	bootstrap = append([]byte(nil), bootstrap...)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return result, failure("manifest-invalid")
	}
	manifestJSON = append(manifestJSON, '\n')
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	s, err := open(ctx)
	if err != nil {
		return result, err
	}
	keep := false
	defer func() {
		if !keep {
			if e := s.Close(); err == nil {
				err = e
			}
		}
	}()
	// No writes precede this all-roots/SCM check, performed through pinned parents.
	if err = s.CheckFresh(ctx); err != nil {
		return result, err
	}
	for _, role := range []objectRole{programFilesApp, programDataApp, setupDirectory} {
		if cancelled(ctx) {
			return result, failure("cancelled")
		}
		result.Retained = true
		if err = s.CreateDirectory(ctx, role); err != nil {
			return result, err
		}
	}
	for _, file := range []struct {
		role  objectRole
		bytes []byte
	}{{serviceFile, payload}, {bootstrapFile, bootstrap}, {manifestFile, manifestJSON}} {
		if cancelled(ctx) {
			return result, failure("cancelled")
		}
		if err = s.WriteFile(ctx, file.role, file.bytes); err != nil {
			return result, err
		}
	}
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	if err = s.Verify(ctx); err != nil {
		return result, err
	}
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	result.Layout, result.BootstrapPath = s.Layout(), s.BootstrapPath()
	result.lease = &lease{session: s}
	keep = true
	return result, nil
}
func cancelled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }
