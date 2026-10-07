//go:build linux

package packagehelper

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/nativeapt"
	"os"
	"path"
	"sort"
	"strings"
)

func (fs protectedFS) identityAuthority() (authority, error) {
	raw, e := fs.read(PolicyPath, 64<<10)
	if e != nil {
		return authority{}, e
	}
	key, e := fs.read(PublicKeyPath, 32)
	if e != nil {
		return authority{}, e
	}
	p, e := DecodePolicy(raw, key)
	if e != nil {
		return authority{}, e
	}
	return authority{p, raw, key, actionpermit.Digest(raw)}, nil
}

// Live admission checks are deliberately separate from historical status access.
func (fs protectedFS) authority() (authority, error) {
	a, e := fs.identityAuthority()
	if e != nil {
		return a, e
	}
	p := a.policy
	for _, pin := range p.Tools {
		d, _, e := fs.hash(pin.Path, 128<<20)
		if e != nil || d != pin.Digest {
			return authority{}, ErrRejected
		}
	}
	unit, e := fs.read(RunnerUnitPath, 16<<10)
	if e != nil || !bytes.Equal(unit, runnerUnitTemplate) {
		return authority{}, ErrRejected
	}
	// Administrator-created review receipt binds the exact updated service-helper
	// artifact and the assertion that its predecessor was quiescent at initialization.
	receipt, e := fs.read(nativeapt.PolicyDirectory+"/service-fence-reviewed", 4096)
	if e != nil || actionpermit.Digest(receipt) != p.ServiceFenceReviewDigest {
		return authority{}, ErrRejected
	}
	expected := []byte("tracebolt-service-helper-shared-fence-v1\n" + p.Tools[0].Digest + "\nlegacy-helper-quiescent-before-initialization\n")
	if !bytes.Equal(receipt, expected) {
		return authority{}, ErrRejected
	}
	if _, _, e = fs.configuration(); e != nil {
		return authority{}, e
	}
	return a, nil
}
func (fs protectedFS) configuration() (string, string, error) {
	var files []nativeapt.SnapshotFile
	for _, p := range []string{"/etc/apt/apt.conf", "/etc/dpkg/dpkg.cfg"} {
		b, e := fs.read(p, 1<<20)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", "", e
		}
		if strings.HasPrefix(p, "/etc/dpkg/") && nativeapt.ValidateDPKGConfig(b) != nil {
			return "", "", ErrRejected
		}
		files = append(files, nativeapt.SnapshotFile{Name: p[1:], Contents: b})
	}
	for _, p := range []string{"/etc/apt/apt.conf.d", "/etc/dpkg/dpkg.cfg.d"} {
		names, e := fs.names(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", "", e
		}
		sort.Strings(names)
		for _, n := range names {
			b, e := fs.read(p+"/"+n, 1<<20)
			if e != nil {
				return "", "", e
			}
			if strings.HasPrefix(p, "/etc/dpkg/") && nativeapt.ValidateDPKGConfig(b) != nil {
				return "", "", ErrRejected
			}
			files = append(files, nativeapt.SnapshotFile{Name: p[1:] + "/" + n, Contents: b})
		}
	}
	host, e := nativeapt.ConfigSnapshotDigest(files)
	if e != nil {
		return "", "", e
	}
	opt, e := fs.read(nativeapt.PolicyDirectory+"/native-opt-in", 256)
	if e != nil || string(opt) != "tracebolt-reviewed-isolated-apt-config-debian13-amd64-v1\n"+host+"\n" {
		return "", "", ErrRejected
	}
	source, e := fs.sourceDigest(nativeapt.PolicyDirectory)
	return host, source, e
}
func (fs protectedFS) sourceDigest(d string) (string, error) {
	s, e := fs.read(d+"/sources.sources", 1<<20)
	if e != nil {
		return "", e
	}
	p, e := fs.read(d+"/preferences", 1<<20)
	if e != nil {
		return "", e
	}
	k, e := fs.read(d+"/keyring.gpg", 8<<20)
	if e != nil {
		return "", e
	}
	return nativeapt.SourceSnapshotDigest(s, p, k)
}
func (fs protectedFS) checkPrepared(b nativeapt.Prepared) error {
	host, source, e := fs.configuration()
	if e != nil || host != b.HostConfigDigest || source != b.SourceSnapshotDigest {
		return ErrRejected
	}
	p, e := nativeapt.JobPaths(b.UpdateID)
	if e != nil {
		return e
	}
	d, e := fs.sourceDigest(p.Snapshot)
	if e != nil || d != source {
		return ErrRejected
	}
	cfg, e := fs.read(p.Config, 64<<10)
	if e != nil || !bytes.Equal(cfg, nativeapt.ConfigBytes(p, b.UpdateID)) {
		return ErrRejected
	}
	empty, e := fs.read(p.Snapshot+"/empty.conf", 1)
	if e != nil || len(empty) != 0 {
		return ErrRejected
	}
	names, e := fs.names(p.Snapshot + "/empty")
	if e != nil || len(names) != 0 {
		return ErrRejected
	}
	return nil
}
func hookPolicyDigest(a authority) string {
	b, _ := json.Marshal(struct {
		Config     string
		Tools      []ToolPin
		Acceptance string
	}{"reviewed-isolated-config-debian13-amd64-v1", a.policy.Tools, a.policy.NativeAcceptanceDigest})
	return actionpermit.Digest(b)
}
func jobFile(id, name string) string { return path.Join(nativeapt.JobRoot, id, name) }
