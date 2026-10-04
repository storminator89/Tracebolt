//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func completeConfig(c Config) Config {
	c.SchemaVersion = CompleteConfigVersion
	c.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	return c
}
func TestCompleteConfigInitializesBothBoundLedgersAndRejectsLoss(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var calls atomic.Int32
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); next.ServeHTTP(w, r) })
			})
			c := completeConfig(f.material.config)
			if c.Validate() != nil || InitializeGuidedState(c) != nil || ValidateGuidedState(c) != nil {
				t.Fatal("fresh dual-ledger handoff rejected")
			}
			before, e := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if e != nil {
				t.Fatal(e)
			}
			for _, version := range []string{ConfigVersion, GuidedConfigVersion, OperationalConfigVersion, PackageConfigVersion} {
				old := c
				old.SchemaVersion = version
				switch version {
				case ConfigVersion, GuidedConfigVersion:
					old.CollectionProfile = ""
				case OperationalConfigVersion:
					old.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
				case PackageConfigVersion:
					old.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
				}
				if InitializeGuidedState(old) == nil {
					t.Fatal("older config adopted new ledger")
				}
			}
			after, _ := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("mismatched init altered metric sequence")
			}
			dir := inventoryStateDirectory(c)
			if os.Rename(dir, dir+"-preserved") != nil || os.Mkdir(dir, 0700) != nil {
				t.Fatal("fixture replacement")
			}
			if ValidateGuidedState(c) == nil {
				t.Fatal("missing inventory sequence domain adopted")
			}
			material, e := loadConfig(c)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Run(context.Background(), material); !errors.Is(e, ErrState) {
				t.Fatal("one-shot collected before validating inventory domain", e)
			}
			if _, e = RunForeground(context.Background(), material, 30*time.Second, nil); !errors.Is(e, agentloop.ErrState) {
				t.Fatal("service collected before validating inventory domain", e)
			}
			if calls.Load() != 0 {
				t.Fatal("invalid inventory state caused network access")
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 {
				t.Fatal("rejected inventory state recreated")
			}
		})
	}
}
func TestCompleteMetricsUseOperationsWithoutTruncatedPackageCapture(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	c := completeConfig(f.material.config)
	collectPackages := func(context.Context, string, time.Time) (linuxpackages.Snapshot, error) {
		t.Fatal("complete metrics performed duplicate prefix collection")
		return linuxpackages.Snapshot{}, nil
	}
	frame, raw, e := collectFrameWithSources(context.Background(), c, 1, unavailableOperations, collectPackages, syntheticPackageBasic)
	if e != nil || frame.Packages != nil || frame.Operational == nil || frame.SchemaVersion != FrameOperationalVersion {
		t.Fatal("complete metrics schema", e)
	}
	parsed, e := lanstore.ValidateFrame(raw, time.Now().UTC())
	if e != nil || !lanstore.FrameMatchesCollectionProfile(parsed, enrollmentcrypto.CollectionProfileComplete) {
		t.Fatal("server rejected fresh complete-profile metric frame", e)
	}
	if _, e := decodeFrameForConfig(raw, 1, packagesConfig(c)); e == nil {
		t.Fatal("package-prefix config adopted complete metric pending bytes")
	}
}
