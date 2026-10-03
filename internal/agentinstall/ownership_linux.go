//go:build linux

package agentinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
)

const ownershipPath = controlDirectory + "/installation-owner.json"

type ownershipRecord struct {
	Version      string       `json:"version"`
	Status       string       `json:"status"`
	Installation installation `json:"installation"`
	StateDevice  uint64       `json:"stateDevice"`
	StateInode   uint64       `json:"stateInode"`
}

func (h *linuxHost) readOwnership() (ownershipRecord, error) {
	var o ownershipRecord
	p := h.path(ownershipPath)
	if e := h.secureFile(p, true, 16384); e != nil {
		return o, e
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		return o, ErrState
	}
	if decodeCanonical(raw, &o) != nil || o.Version != "tracebolt.agent-install-owner.v1" || (o.Status != "preparing" && o.Status != "prepared" && o.Status != "installed" && o.Status != "uninstalled") || !validAccountID(o.Installation.UID) || !validAccountID(o.Installation.GID) {
		return o, ErrState
	}
	// Exact root-owned local record is still validated before it can authorize paths.
	m := o.Installation
	if m.Version != "tracebolt.agent-installation.v1" || (m.Profile != "tls" && m.Profile != "http-test") {
		return o, ErrState
	}
	for _, d := range []string{m.AgentHash, m.EnrollHash, m.SourceHash, m.BootstrapHash, m.UnitHash} {
		if !validDigest(d) {
			return o, ErrState
		}
	}
	return o, nil
}
func (h *linuxHost) validateStateDomain(o ownershipRecord) error {
	i, e := os.Lstat(h.path(StateDirectory))
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0700 {
		return ErrState
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != o.Installation.UID || int(s.Gid) != o.Installation.GID || o.StateDevice != uint64(s.Dev) || o.StateInode != s.Ino || o.StateInode == 0 {
		return ErrState
	}
	return nil
}
func (h *linuxHost) validateRetained(o ownershipRecord) error {
	if o.Status != "prepared" && o.Status != "uninstalled" {
		return ErrState
	}
	if h.validateStateDomain(o) != nil {
		return ErrState
	}
	for _, p := range []string{InstallDirectory, publicDirectory} {
		if h.secureDirectory(h.path(p), false) != nil {
			return ErrState
		}
	}
	if h.secureFile(h.path(BootstrapPath), false, 64<<10) != nil {
		return ErrState
	}
	raw, e := os.ReadFile(h.path(BootstrapPath))
	if e != nil || sum(raw) != o.Installation.BootstrapHash {
		return ErrState
	}
	for _, p := range []string{AgentPath, EnrollPath, UnitPath, ManifestPath} {
		if _, e := os.Lstat(h.path(p)); !os.IsNotExist(e) {
			return ErrState
		}
	}
	return nil
}
func (t *linuxTransaction) updateOwnership(status string, m installation) error {
	old, e := t.h.readOwnership()
	if e != nil {
		return e
	}
	old.Status = status
	old.Installation = m
	return t.changeBytes(ownershipPath, encode(old), 0600)
}
func (t *linuxTransaction) removedAlready() bool {
	o, e := t.h.readOwnership()
	return e == nil && o.Status == "uninstalled" && t.r.Action == Uninstall && t.h.validateRetained(o) == nil
}
func (t *linuxTransaction) createOwnership(m installation) error {
	o := ownershipRecord{Version: "tracebolt.agent-install-owner.v1", Status: "preparing", Installation: m}
	if exclusiveBytes(t.h.path(ownershipPath), encode(o), 0600) != nil {
		return ErrState
	}
	return nil
}
func (t *linuxTransaction) markPrepared() error {
	o, e := t.h.readOwnership()
	if e != nil {
		return e
	}
	i, e := os.Lstat(t.h.path(StateDirectory))
	if e != nil {
		return ErrState
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrState
	}
	o.StateDevice = uint64(s.Dev)
	o.StateInode = s.Ino
	o.Status = "prepared"
	if writePrivateAtomic(t.h.path(ownershipPath), encode(o), 0600) != nil {
		return ErrState
	}
	return syncDirectory(filepath.Dir(t.h.path(ownershipPath)))
}

func decodeCanonical(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrState
	}
	encoded, e := json.Marshal(out)
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), encoded) {
		return ErrState
	}
	return nil
}
