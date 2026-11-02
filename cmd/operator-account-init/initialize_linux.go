//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/operatorauth"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func privateDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for dir, leaf := path, true; ; dir, leaf = filepath.Dir(dir), false {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return false
		}
		if leaf && (st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0) {
			return false
		}
		if dir == filepath.Dir(dir) {
			return true
		}
	}
}
func within(path, dir string) bool {
	relative, err := filepath.Rel(dir, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
func absent(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}
func createDurable(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = operatorauth.ErrAuthorityUncertain
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr = d.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func initialize(o options) string {
	if os.Geteuid() != o.runtimeUID || o.runtimeUID <= 0 {
		return "runtime_uid"
	}
	c, err := lanconfig.LoadConfig(o.lanConfig)
	if err != nil || c.Profile != lanconfig.TLS {
		return "lan_config"
	}
	if !filepath.IsAbs(o.output) || filepath.Clean(o.output) != o.output || !privateDirectory(filepath.Dir(o.output)) || !privateDirectory(c.StateDirectory) {
		return "protected_directories"
	}
	if within(o.output, c.WebDirectory) || within(o.output, c.StateDirectory) || within(c.StateDirectory, c.WebDirectory) || within(c.WebDirectory, c.StateDirectory) || within(c.OperatorAuthFile, c.WebDirectory) || o.output == o.lanConfig || o.output == c.OperatorAuthFile {
		return "path_separation"
	}
	ops, err := lanconfig.LoadNamedOperatorSeed(c.OperatorAuthFile, c.Profile)
	if err != nil {
		return "named_seed"
	}
	marker := filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile)
	journal := filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityJournalFile)
	if !absent(o.output, marker, journal) {
		return "existing_authority"
	}
	// Reuse the SAME state-directory flock as the running manager, never another
	// lock file or a source-only semaphore. State already exists and is private.
	lease, err := lanstore.AcquireManagerWriter(c.StateDirectory)
	if err != nil {
		return "manager_writer"
	}
	defer lease.Close()
	if !absent(o.output, marker, journal) {
		return "existing_authority"
	}
	if lease.Check() != nil {
		return "manager_writer"
	}
	// Establish/validate the same profile binding used by normal manager startup
	// before any authority artifact makes an empty directory nonempty. Never
	// adopt an unmarked nonempty state or an incompatible existing profile.
	if err = lanstore.PrepareProfileDirectory(c.StateDirectory, c.Profile); err != nil {
		return "profile_state"
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "authority_identity"
	}
	reference := lanconfig.AccountAuthorityReference{SchemaVersion: lanconfig.AccountAuthorityVersion, Profile: c.Profile, AuthorityID: "authority_" + hex.EncodeToString(id[:]), AuthorityFile: journal}
	markerRaw, err := lanconfig.AccountAuthorityMarkerBytes(c.StateDirectory, reference)
	if err != nil {
		return "authority_identity"
	}
	refRaw, err := json.Marshal(reference)
	if err != nil {
		return "reference_encoding"
	}
	initial := operatorauth.AccountSnapshot{Version: operatorauth.AccountVersion, AuthorityID: reference.AuthorityID, Profile: reference.Profile, Revision: 1, Accounts: make([]operatorauth.AccountRecord, len(ops))}
	for i, op := range ops {
		initial.Accounts[i] = operatorauth.AccountRecord{Operator: op, Revision: 1}
	}
	// After profile admission, the permanent authority fence is durable FIRST.
	// Any subsequent failure blocks both
	// silent v2 fallback and blind reseeding. Nothing is deleted on any failure.
	if lease.Check() != nil {
		return "manager_writer"
	}
	if err = createDurable(marker, append(markerRaw, '\n')); err != nil {
		return "marker_uncertain"
	}
	store, err := operatorauth.CreateAccountJournal(journal, initial)
	if err != nil {
		return "journal_uncertain"
	}
	if err = store.Close(); err != nil {
		return "journal_uncertain"
	}
	if err = createDurable(o.output, append(refRaw, '\n')); err != nil {
		return "reference_uncertain"
	}
	return "created"
}
