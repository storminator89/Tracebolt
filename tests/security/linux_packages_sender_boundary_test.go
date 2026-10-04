//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/operational"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// These use ordinary disposable generated credentials and a pre-staged wholly
// synthetic current frame. Run takes the pending-only path, so no basic,
// operational or package collector is reached. The owned loopback handler is a
// receipt stub, not an enrollment-store/API acceptance test.
func TestIndependentPackageSenderPendingOnlyExactBytesAcrossRuns(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	var agentID string
	var firstReceived time.Time
	fixture := newForegroundBoundaryFixture(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				t.Error("ordinary TLS client identity missing")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, lanstore.MaxFrameBytes+1))
			f, parseErr := lanstore.ValidateFrame(raw, time.Now().UTC())
			if err != nil || parseErr != nil || f.SchemaVersion != lanstore.FramePackagesVersion {
				t.Error("synthetic current package frame rejected")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			bodies = append(bodies, bytes.Clone(raw))
			first := len(bodies) == 1
			if first {
				firstReceived = time.Now().UTC()
			}
			received := firstReceived
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: agentID,
				Sequence: f.Sequence, CollectedAt: f.Observation.Observation.LastSeen, ReceivedAt: received, Duplicate: true})
		})
	})
	agentID = fixture.config.AgentID
	c := fixture.config
	c.SchemaVersion, c.CollectionProfile = lanclient.PackageConfigVersion, enrollmentcrypto.CollectionProfilePackages
	if lanclient.InitializeGuidedState(c) != nil {
		t.Fatal("fresh disposable package sender state failed")
	}
	public, err := os.ReadFile(c.CertificateFile)
	if err != nil {
		t.Fatal("generated public fixture certificate unavailable")
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("generated public certificate decoding failed")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("generated public certificate parsing failed")
	}
	hash := sha256.Sum256([]byte("tracebolt.sender-binding.v4\n" + c.CollectionProfile + "\n" + c.Profile + "\n" + c.ManagerOrigin + "\n" + lantrust.Fingerprint(leaf) + "\n" + c.AgentID))
	binding := hex.EncodeToString(hash[:])
	configPath := filepath.Join(t.TempDir(), "sender.json")
	if os.WriteFile(configPath, packageReviewJSON(t, c), 0600) != nil {
		t.Fatal("synthetic sender config write failed")
	}
	material, err := lanclient.Load(configPath)
	if err != nil {
		t.Fatal("synthetic package material failed")
	}
	f, _ := packageReviewFrame()
	now := time.Now().UTC()
	f.Observation.GeneratedAt, f.Observation.Observation.LastSeen = now, now
	f.Observation.Observation.CPU.CollectedAt, f.Observation.Observation.Memory.CollectedAt, f.Observation.Observation.Disk.CollectedAt = now, now, now
	op := operational.Empty(now, operational.ReasonNotImplemented)
	f.Operational = &op
	f.Packages.GenerationID, f.Packages.CollectedAt = op.GenerationID, now
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal("synthetic frame encoding failed")
	}
	raw = append(raw, '\n')
	if _, err := lanstore.ValidateFrame(raw, now); err != nil {
		t.Fatal("pending-only fixture must fit current exact contract")
	}
	state, err := lanclientstate.OpenExisting(c.StateDirectory, binding)
	if err != nil {
		t.Fatal("explicitly bound package ledger did not open")
	}
	pending, err := state.Stage(1, raw)
	state.Close()
	if err != nil {
		t.Fatal("synthetic staging failed")
	}
	first, err := lanclient.Run(context.Background(), material)
	if !errors.Is(err, lanclient.ErrTransport) || !first.RetriedPending || first.Sequence != 1 || first.DiscardedStale {
		t.Fatal("pending-only first run changed collection or sequence")
	}
	state, err = lanclientstate.OpenExisting(c.StateDirectory, binding)
	if err != nil {
		t.Fatal("retained package ledger did not reopen")
	}
	retained, err := state.Pending()
	state.Close()
	if err != nil || retained == nil || retained.Digest != pending.Digest || !bytes.Equal(retained.Body(), raw) {
		t.Fatal("failed delivery changed exact staged bytes")
	}
	second, err := lanclient.Run(context.Background(), material)
	if err != nil || !second.RetriedPending || !second.Duplicate || second.Sequence != 1 || second.DiscardedStale {
		t.Fatal("exact pending retry failed")
	}
	mu.Lock()
	equal := len(bodies) == 2 && bytes.Equal(bodies[0], raw) && bytes.Equal(bodies[1], raw)
	mu.Unlock()
	if !equal {
		t.Fatal("pending retry normalized or regenerated frame")
	}
	state, err = lanclientstate.OpenExisting(c.StateDirectory, binding)
	if err != nil {
		t.Fatal("acknowledged ledger did not reopen")
	}
	defer state.Close()
	retained, err = state.Pending()
	next, seqErr := state.NextSequence()
	if err != nil || seqErr != nil || retained != nil || next != 2 {
		t.Fatal("receipt failed to clear exact request or preserve sequence floor")
	}
}

func TestIndependentPackageProfileManagerMarkerIsolation(t *testing.T) {
	// Fixed-binding marker checks only, with the existing ordinary disposable
	// config fixture. No store/API startup, live key or source collection occurs.
	for _, transport := range []string{"tls", "http-test"} {
		for _, older := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational} {
			t.Run(transport+"/"+older, func(t *testing.T) {
				f := newEnrollmentConfigFixture(t, transport)
				f.config.CollectionProfile = older
				f.save(t)
				old := f.load(t)
				if old.PrepareMode(f.lan.Config.StateDirectory, 0) != nil {
					t.Fatal("old profile marker setup failed")
				}
				marker := filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)
				before, err := os.ReadFile(marker)
				if err != nil {
					t.Fatal("old marker unavailable")
				}
				f.config.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
				f.save(t)
				packages := f.load(t)
				if packages.PrepareMode(f.lan.Config.StateDirectory, 0) == nil {
					t.Fatal("package profile adopted an older manager marker")
				}
				after, err := os.ReadFile(marker)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("rejected package profile rewrote old marker")
				}
				f.lan.Config.StateDirectory = filepath.Join(t.TempDir(), "fresh-package-profile")
				if os.Mkdir(f.lan.Config.StateDirectory, 0700) != nil {
					t.Fatal("fresh marker directory setup failed")
				}
				fresh := f.load(t)
				if fresh.StoreConfig().Binding.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || fresh.PrepareMode(f.lan.Config.StateDirectory, 0) != nil {
					t.Fatal("fresh explicit package manager marker rejected")
				}
				marker = filepath.Join(f.lan.Config.StateDirectory, enrollmentconfig.ModeFile)
				before, err = os.ReadFile(marker)
				if err != nil {
					t.Fatal("fresh package marker unavailable")
				}
				f.config.CollectionProfile = older
				f.save(t)
				if f.load(t).PrepareMode(f.lan.Config.StateDirectory, 0) == nil {
					t.Fatal("older profile adopted a package manager marker")
				}
				after, err = os.ReadFile(marker)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("rejected old profile rewrote package marker")
				}
			})
		}
	}
}
