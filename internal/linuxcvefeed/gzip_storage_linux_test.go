//go:build linux

package linuxcvefeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/linuxcve"
	"localrmm/internal/linuxpackages"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCompressedCacheFailuresKeepDiskAndMemory(t *testing.T) {
	c, store, dir := newCache(t)
	wire := gzipFixture(t, []byte(debianFixture("1.2-3")))
	c.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return gzipResponse(wire), nil })
	old, err := c.FetchDebian(context.Background(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(old, store, testNow); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "debian-security-tracker.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cacheEnvelope
	if json.Unmarshal(before, &envelope) != nil || envelope.Kind != officialGzipKind {
		t.Fatal("official cache was not compressed")
	}
	beforeMetadata := store.Snapshot(linuxpackages.Debian13).Metadata(testNow)
	wire[len(wire)-8] ^= 1
	if _, err = c.FetchDebian(context.Background(), testNow.Add(time.Hour)); !errors.Is(err, ErrResponse) {
		t.Fatal("bad CRC accepted", err)
	}
	wire = gzipFixture(t, []byte(debianFixture("1.2-4")))
	next, err := c.FetchDebian(context.Background(), testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	disk := c.disk.(*linuxStorage)
	rename := disk.rename
	disk.rename = func(int, string, int, string, uint) error { return unix.EIO }
	err = c.Commit(next, store, testNow.Add(time.Hour))
	disk.rename = rename
	if !errors.Is(err, ErrIO) {
		t.Fatal("write failure lost", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed gzip update changed last-good disk")
	}
	if current := store.Snapshot(linuxpackages.Debian13).Metadata(testNow); current.SHA256 != beforeMetadata.SHA256 || !current.FetchedAt.Equal(beforeMetadata.FetchedAt) {
		t.Fatal("failed gzip update changed memory")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restored := &linuxcve.Store{}
	later := testNow.Add(72 * time.Hour)
	if err = restarted.Load(context.Background(), restored, later); err != nil {
		t.Fatal(err)
	}
	m := restored.Snapshot(linuxpackages.Debian13).Metadata(later)
	if m.SHA256 != beforeMetadata.SHA256 || !m.FetchedAt.Equal(beforeMetadata.FetchedAt) || !m.ExpiresAt.Equal(beforeMetadata.ExpiresAt) || m.Trust != "https_origin_only" || m.Freshness != "stale" {
		t.Fatal("gzip restart lost original identity/age")
	}
}

func TestLegacyDiskCacheReloadAndCompressedUpgrade(t *testing.T) {
	c, _, dir := newCache(t)
	raw := []byte(" \n" + debianFixture("1.2-3") + "\n")
	legacy := cacheEnvelope{SchemaVersion: cacheSchema, Provider: linuxcve.DebianProvider, Kind: officialKind, FetchedAt: testNow, SHA256: testDigest(raw), PayloadSHA256: testDigest(bytes.TrimSpace(raw)), Data: raw}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("decodedSha256")) {
		t.Fatal("legacy encoding changed")
	}
	if err = c.disk.replace("debian-security-tracker.json", encoded); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store := &linuxcve.Store{}
	if err = c.Load(context.Background(), store, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	m := store.Snapshot(linuxpackages.Debian13).Metadata(testNow.Add(time.Hour))
	if m.SHA256 != legacy.PayloadSHA256 || m.Trust != "https_origin_only" || !m.FetchedAt.Equal(testNow) {
		t.Fatal("legacy disk metadata changed")
	}
	c.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(debianFixture("1.2-4")), nil })
	next, err := c.FetchDebian(context.Background(), testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Commit(next, store, testNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(filepath.Join(dir, "debian-security-tracker.json"))
	if err != nil {
		t.Fatal(err)
	}
	var e cacheEnvelope
	if json.Unmarshal(updated, &e) != nil || e.Kind != officialGzipKind || len(e.DecodedSHA256) != 64 || e.SHA256 != testDigest(e.Data) {
		t.Fatal("legacy cache did not upgrade to verified compressed bytes")
	}
}
