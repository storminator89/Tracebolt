//go:build darwin

package macosservice

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"localrmm/internal/agentidentity"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"path"
	"runtime"
)

type nativeBackend struct{}

func NewNativeBackend() Backend { return nativeBackend{} }

func (nativeBackend) Inspect(ctx context.Context, r Request) ([]Check, error) {
	checks := []Check{}
	check := func(code, detail string, ok bool) bool {
		checks = append(checks, Check{Code: code, Passed: ok, Detail: detail})
		return ok
	}
	fail := func() ([]Check, error) { return checks, ErrPreflight }
	if ctx == nil || ctx.Err() != nil {
		return fail()
	}
	uid, gid, valid := identity(r.ServiceIdentity)
	if !check("platform", "Requires native macOS amd64 or arm64; source/cross-build checks are not native acceptance.", runtime.GOOS == "darwin" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")) {
		return fail()
	}
	if !check("service-identity", "Run preflight as the selected dedicated nonroot UID:GID with matching real/effective/saved IDs and no supplementary groups beyond that GID; never as root or an ordinary user.", valid && agentidentity.Validate(r.ServiceIdentity)) {
		return fail()
	}
	mapped := inspectDedicatedAccount(ctx, uid, gid, readLocalAccount)
	if !check("dedicated-account", "Fixed read-only local Directory Service queries must map the existing _traceboltagent user and group to the reviewed numeric UID:GID. No account or group is created or modified.", mapped) {
		return fail()
	}
	var dirs []*protectedPath
	defer func() {
		for _, d := range dirs {
			d.close()
		}
	}()
	pathsOK := true
	for _, name := range []string{InstallDirectory, StateDirectory, EnrollmentDirectory, EnrollmentDirectory + "/telemetry", path.Dir(PlistPath)} {
		d, err := openProtected(name, true, uid, gid, false, 0)
		if err != nil {
			pathsOK = false
			break
		}
		dirs = append(dirs, d)
	}
	if !check("protected-paths", "Require root-owned nonwritable installation/LaunchDaemons parent chains and selected UID:GID-owned 0700 state, enrollment and telemetry directories, with supported local filesystems and no permissive ACLs or symlinks.", pathsOK) {
		return fail()
	}
	binary, err := openProtected(AgentPath, false, uid, gid, true, MaxBinaryBytes)
	binaryOK := false
	if err == nil {
		binaryOK = inspectBinary(ctx, binary.file, binary.nodes[len(binary.nodes)-1].stat.Size, r.AgentSHA256, runtime.GOARCH) == nil && binary.stable()
		binary.closeArtifact()
	}
	if !check("agent-artifact", "Require the exact independently reviewed SHA-256 of a protected root-owned native macos-agent Mach-O/Go binary for this architecture. This does not verify signing, notarization or publisher authenticity.", binaryOK) {
		return fail()
	}
	source, err := openProtected(r.SourceArchive, false, uid, gid, false, MaxSourceBytes)
	sourceOK := false
	if err == nil {
		sourceOK = hashArtifact(ctx, source.file, source.nodes[len(source.nodes)-1].stat.Size, r.SourceSHA256) == nil && source.stable()
		source.closeArtifact()
	}
	if !check("source-artifact", "Require an independently selected SHA-256 for the bounded protected root-owned source archive; it is never extracted or executed and does not prove reproducible builds.", sourceOK) {
		return fail()
	}
	if !check("activated-enrollment", "Require the explicitly selected existing activated basic or fresh inventory TLS handoff at the exact fixed paths, valid current certificate and original protected sender state. No enrollment, network, collection, key or ledger creation occurs.", validateEnrollment(ctx, selectedProfile(r)) == nil) {
		return fail()
	}
	parent := dirs[len(dirs)-1]
	var existing unix.Stat_t
	absent := unix.Fstatat(parent.nodes[len(parent.nodes)-1].fd, path.Base(PlistPath), &existing, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT
	for _, d := range dirs {
		absent = absent && d.stable()
	}
	if !check("plist-absent", "The fixed plist path must be absent. Existing files, symlinks and uncertain reads block this fresh candidate. The native launchd job registry is not inspected.", absent) {
		return fail()
	}
	if !check("final-identity", "Recheck the exact service identity and uncanceled request after local inspection; no earlier result authorizes a later native action.", ctx.Err() == nil && agentidentity.Validate(r.ServiceIdentity)) {
		return fail()
	}
	return checks, nil
}

func validateEnrollment(ctx context.Context, profile string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrPreflight
	}
	raw, err := lanconfig.ReadProtected(ConfigPath, true, 16384)
	if err != nil {
		return ErrPreflight
	}
	inventory := func(path string) error {
		return enrollmentclient.ValidateMacOSInventoryServicePreflight(ctx, path)
	}
	if validateSelectedHandoff(raw, profile, lanclient.ValidateGuidedHandoff, inventory) != nil {
		return ErrPreflight
	}
	after, err := lanconfig.ReadProtected(ConfigPath, true, 16384)
	if err != nil || !bytes.Equal(raw, after) || ctx.Err() != nil {
		return ErrPreflight
	}
	return nil
}
