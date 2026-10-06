//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/socketowner"
	"localrmm/internal/systemstate"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Real filesystem operations here are confined to newly generated temporary
// synthetic files. Identity is injected, never a native collector/helper or an
// installed service, account, cgroup, procfs, socket or host command.
func newSocketSetupDiskFixture(t *testing.T) (*socketFixture, socketSetupHooks) {
	t.Helper()
	f := newSocketFixture(t)
	f.sender.Close()
	if err := os.Rename(socketOwnerConsentPath(f.material), socketOwnerConsentPath(f.material)+".fixture-preserved"); err != nil {
		t.Fatal(err)
	}
	h := defaultSocketSetupHooks()
	h.material = func(path string) (Material, uint32, uint32, error) {
		if path != SocketOwnerSetupConfigPath {
			t.Fatal("not fixed config")
		}
		m, err := loadActionSetupMaterial(f.path)
		m.configPath = SocketOwnerSetupConfigPath
		return m, 1234, 1234, err
	}
	return f, h
}
func socketSetupDiskRun(h socketSetupHooks, mode string, p socketowner.Policy) (SocketOwnerSetupResult, error) {
	var raw []byte
	ack := SocketOwnerSetupAcknowledgements{}
	if mode == "initialize" || mode == "disable" {
		p.Enabled = mode == "initialize"
		raw, _ = socketowner.EncodePolicy(p)
		if mode == "initialize" {
			ack = SocketOwnerSetupAcknowledgements{true, true, p.TransportProfile == "http-test"}
		}
	}
	return configureSocketOwners(context.Background(), mode, raw, ack, h)
}
func TestSocketSetupDiskLifecycleProducerAndStoppedLocks(t *testing.T) {
	for _, locked := range []string{"sender", "system", "none"} {
		t.Run(locked, func(t *testing.T) {
			f, h := newSocketSetupDiskFixture(t)
			var held io.Closer
			var err error
			if locked == "sender" {
				held, err = lanclientstate.AcquireInspection(f.material.config.StateDirectory, f.material.binding)
			}
			if locked == "system" {
				held, err = systemstate.OpenExistingNoRecovery(systemStateDirectory(f.material.config), systemStateBinding(f.material))
			}
			if err != nil {
				t.Fatal(err)
			}
			if held != nil {
				defer held.Close()
			}
			before := setupSnapshot(t, filepath.Dir(f.path))
			got, err := socketSetupDiskRun(h, "initialize", f.local.Policy)
			if locked != "none" {
				if err == nil || got != (SocketOwnerSetupResult{}) {
					t.Fatal("active owner accepted")
				}
				after := setupSnapshot(t, filepath.Dir(f.path))
				if !sameSocketSetupFiles(before, after) {
					t.Fatal("locked setup wrote")
				}
				return
			}
			if err != nil || got.State != "enabled" {
				t.Fatal(got, err)
			}
			st, err := os.Lstat(socketOwnerConsentPath(f.material))
			if err != nil || st.Mode().Perm() != 0600 {
				t.Fatal("consent mode", err)
			}
			preview, err := socketSetupDiskRun(h, "preview", f.local.Policy)
			if err != nil || preview.Policy == nil || *preview.Policy != f.local.Policy {
				t.Fatal(preview, err)
			}
			got, err = socketSetupDiskRun(h, "disable", f.local.Policy)
			if err != nil || got.State != "disabled" || got.TaggedPendingDiscarded {
				t.Fatal(got, err)
			}
			raw, err := os.ReadFile(socketOwnerConsentPath(f.material))
			var c SocketOwnerConsent
			if err != nil || json.Unmarshal(raw, &c) != nil || c.Policy.Enabled {
				t.Fatal("missing terminal tombstone")
			}
			after := setupSnapshot(t, filepath.Dir(f.path))
			delete(after, socketOwnerConsentPath(f.material))
			if !sameSocketSetupFiles(before, after) {
				t.Fatal("unrelated state changed")
			}
		})
	}
}
func sameSocketSetupFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}
func TestSocketSetupDiskExistingTemporaryCorruptAndForeignReject(t *testing.T) {
	for _, kind := range []string{"enabled", "disabled", "corrupt", "sidecar_temp", "system_temp", "symlink", "hardlink", "wrongmode", "ready", "metrics", "inventory", "system", "renewal"} {
		t.Run(kind, func(t *testing.T) {
			f, h := newSocketSetupDiskFixture(t)
			path := socketOwnerConsentPath(f.material)
			switch kind {
			case "enabled":
				f.writeConsent()
			case "disabled":
				f.local.Policy.Enabled = false
				f.writeConsent()
				f.local.Policy.Enabled = true
			case "corrupt":
				f.write(path, []byte(`{}`))
			case "sidecar_temp":
				f.write(filepath.Join(f.material.config.StateDirectory, socketSetupTemp), []byte("incomplete fixture"))
			case "system_temp":
				f.write(filepath.Join(systemStateDirectory(f.material.config), ".system-state.tmp"), []byte("incomplete fixture"))
			case "symlink":
				if os.Symlink(path+".fixture-preserved", path) != nil {
					t.Fatal("fixture symlink")
				}
			case "hardlink":
				if os.Link(path+".fixture-preserved", path) != nil {
					t.Fatal("fixture hardlink")
				}
			case "wrongmode":
				if os.WriteFile(path, []byte(`{}`), 0644) != nil {
					t.Fatal("fixture mode")
				}
			case "ready":
				f.write(filepath.Join(filepath.Dir(f.path), "ready.json"), []byte(`{}`))
			case "metrics":
				f.write(filepath.Join(f.material.config.StateDirectory, "state.json"), []byte(`{}`))
			case "inventory":
				f.write(filepath.Join(inventoryStateDirectory(f.material.config), "inventory-state.json"), []byte(`{}`))
			case "system":
				f.write(filepath.Join(systemStateDirectory(f.material.config), "system-state.json"), []byte(`{}`))
			case "renewal":
				f.writeCertificate(2)
				f.writeConfig(f.material.config)
			}
			before := setupSnapshot(t, filepath.Dir(f.path))
			got, err := socketSetupDiskRun(h, "initialize", f.local.Policy)
			if err == nil || got != (SocketOwnerSetupResult{}) || !sameSocketSetupFiles(before, setupSnapshot(t, filepath.Dir(f.path))) {
				t.Fatal("repaired/adopted existing state", kind, err)
			}
		})
	}
}
func TestSocketSetupDiskWriterFailureRetainsEvidence(t *testing.T) {
	for _, phase := range []string{"short_write", "write_error", "file_sync", "rename", "directory_sync", "readback", "identity_before_commit", "noreplace_race"} {
		t.Run(phase, func(t *testing.T) {
			f, h := newSocketSetupDiskFixture(t)
			ops := socketSetupDefaultFileOps()
			originalSync := ops.sync
			originalRename := ops.rename
			syncs := 0
			switch phase {
			case "short_write":
				ops.write = func(file *os.File, raw []byte) (int, error) { return file.Write(raw[:len(raw)/2]) }
			case "write_error":
				ops.write = func(file *os.File, raw []byte) (int, error) {
					file.Write(raw[:4])
					return 4, errors.New("fixture private write error")
				}
			case "file_sync", "directory_sync":
				ops.sync = func(fd int) error {
					syncs++
					if phase == "file_sync" && syncs == 1 || phase == "directory_sync" && syncs == 2 {
						return unix.EIO
					}
					return originalSync(fd)
				}
			case "rename":
				ops.rename = func(int, string, int, string, bool) error { return unix.EIO }
			case "readback":
				ops.rename = func(a int, b string, c int, d string, create bool) error {
					if err := originalRename(a, b, c, d, create); err != nil {
						return err
					}
					f.write(socketOwnerConsentPath(f.material), []byte(`{}`))
					return nil
				}
			case "noreplace_race":
				ops.rename = func(a int, b string, c int, d string, create bool) error {
					f.write(socketOwnerConsentPath(f.material), []byte("foreign fixture"))
					return originalRename(a, b, c, d, create)
				}
			case "identity_before_commit":
				ops.write = func(file *os.File, raw []byte) (int, error) {
					f.write(filepath.Join(filepath.Dir(f.path), "ready.json"), []byte(`{}`))
					return file.Write(raw)
				}
			}
			h.write = func(m Material, o *SocketOwnerConsent, n SocketOwnerConsent, current func() error) error {
				return writeSocketSetupConsentUsing(m, o, n, current, ops)
			}
			got, err := socketSetupDiskRun(h, "initialize", f.local.Policy)
			if !errors.Is(err, ErrSocketOwnerSetupIncomplete) || got != (SocketOwnerSetupResult{}) {
				t.Fatal("failure claimed completion", phase, err)
			}
			if phase != "directory_sync" && phase != "readback" {
				if _, err := os.Lstat(filepath.Join(f.material.config.StateDirectory, socketSetupTemp)); err != nil {
					t.Fatal("failure erased temporary")
				}
			}
			if phase == "noreplace_race" {
				raw, _ := os.ReadFile(socketOwnerConsentPath(f.material))
				if string(raw) != "foreign fixture" {
					t.Fatal("no-replace overwritten")
				}
			}
			before := setupSnapshot(t, filepath.Dir(f.path))
			if _, err := socketSetupDiskRun(h, "initialize", f.local.Policy); err == nil || !sameSocketSetupFiles(before, setupSnapshot(t, filepath.Dir(f.path))) {
				t.Fatal("incomplete install silently replayed")
			}
		})
	}
}
func TestSocketSetupDiskDisablePreservesTombstoneOnDiscardFailure(t *testing.T) {
	f, h := newSocketSetupDiskFixture(t)
	if _, err := socketSetupDiskRun(h, "initialize", f.local.Policy); err != nil {
		t.Fatal(err)
	}
	fake := newSocketSetupMemoryFixture(t, "http-test")
	fake.m = f.material
	fake.policy = f.local.Policy
	fake.pending(t, true)
	fake.state.discardErr = systemstate.ErrIO
	h.state = func(Material) (socketSetupState, error) { return fake.state, nil }
	got, err := socketSetupDiskRun(h, "disable", f.local.Policy)
	if !errors.Is(err, ErrSocketOwnerSetupDisableIncomplete) || got != (SocketOwnerSetupResult{}) || fake.state.p == nil || fake.state.floor != 7 {
		t.Fatal("uncertain discard", err)
	}
	c, err := inspectSocketSetupConsent(f.material)
	if err != nil || c == nil || c.Policy.Enabled {
		t.Fatal("tombstone missing")
	}
	before := setupSnapshot(t, filepath.Dir(f.path))
	if _, err := socketSetupDiskRun(h, "disable", f.local.Policy); err == nil || !sameSocketSetupFiles(before, setupSnapshot(t, filepath.Dir(f.path))) {
		t.Fatal("implicit drain retry")
	}
}
func TestSocketSetupDiskConsentCanonicalAndForeignDisabled(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, '\n') },
		func(b []byte) []byte { return []byte(strings.Replace(string(b), `"version":`, `"Version":`, 1)) },
		func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"enabled":true`, `"enabled":false,"enabled":false`, 1))
		},
	} {
		f, h := newSocketSetupDiskFixture(t)
		raw, _ := json.Marshal(f.local)
		f.write(socketOwnerConsentPath(f.material), mutate(raw))
		if _, err := socketSetupDiskRun(h, "preview", f.local.Policy); err == nil {
			t.Fatal("noncanonical accepted")
		}
	}
}

func TestSocketSetupDiskDisableNativeLedgerTaggedOnlyFloorAndReadback(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		name := "ordinary"
		if tagged {
			name = "tagged"
		}
		t.Run(name, func(t *testing.T) {
			f, h := newSocketSetupDiskFixture(t)
			if _, err := socketSetupDiskRun(h, "initialize", f.local.Policy); err != nil {
				t.Fatal(err)
			}
			invented := newSocketSetupMemoryFixture(t, "http-test")
			invented.m = f.material
			invented.policy = f.local.Policy
			invented.state.floor = 1
			invented.pending(t, tagged)
			dir, binding := systemStateDirectory(f.material.config), systemStateBinding(f.material)
			state, err := systemstate.OpenExistingNoRecovery(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := state.Stage(1, invented.state.p.body)
			if err != nil {
				t.Fatal(err)
			}
			state.Close()
			got, err := socketSetupDiskRun(h, "disable", f.local.Policy)
			if err != nil || got.State != "disabled" || got.TaggedPendingDiscarded != tagged {
				t.Fatal(got, err)
			}
			state, err = systemstate.OpenExistingNoRecovery(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			n, err := state.NextSequence()
			if err != nil || n != 2 {
				t.Fatal("consumed floor reset")
			}
			retained, err := state.Pending()
			if err != nil {
				t.Fatal(err)
			}
			if tagged && retained != nil || !tagged && (retained == nil || retained.Digest != pending.Digest || !bytes.Equal(retained.Body(), pending.Body())) {
				t.Fatal("wrong body discarded")
			}
		})
	}
}
