//go:build linux

package lanclient

import (
	"context"
	"errors"
	"localrmm/internal/agentloop"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuidedSenderNeverInitializesMissingLedger(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var calls atomic.Int32
			f := integrationFixture(t, profile, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); next.ServeHTTP(w, r) })
			})
			cfg := f.material.config
			cfg.SchemaVersion = GuidedConfigVersion
			m, e := loadConfig(cfg)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Run(context.Background(), m); !errors.Is(e, ErrState) {
				t.Fatal("uninitialized guided sender accepted")
			}
			if _, e = os.Lstat(cfg.StateDirectory); !os.IsNotExist(e) {
				t.Fatal("guided startup created missing state directory")
			}
			if calls.Load() != 0 {
				t.Fatal("uninitialized guided sender contacted manager")
			}
			if e = InitializeGuidedState(cfg); e != nil {
				t.Fatal("one-time guided initialization", e)
			}
			if e = ValidateGuidedState(cfg); e != nil {
				t.Fatal("initialized ledger rejected", e)
			}
			report, e := Run(context.Background(), m)
			if e != nil || report.Sequence != 1 {
				t.Fatal("initialized guided report failed", e)
			}
			if os.Rename(cfg.StateDirectory, cfg.StateDirectory+"-preserved") != nil || os.Mkdir(cfg.StateDirectory, 0700) != nil {
				t.Fatal("replacement fixture")
			}
			if _, e = Run(context.Background(), m); !errors.Is(e, ErrState) {
				t.Fatal("empty replacement reset guided sequence")
			}
			if _, e = RunForeground(context.Background(), m, 15*time.Second, nil); !errors.Is(e, agentloop.ErrState) {
				t.Fatal("foreground reset guided sequence")
			}
			if e = ValidateGuidedState(cfg); !errors.Is(e, ErrState) {
				t.Fatal("resumed handoff accepted replacement")
			}
			entries, _ := os.ReadDir(cfg.StateDirectory)
			if len(entries) != 0 || calls.Load() != 1 {
				t.Fatal("rejected replacement modified or contacted manager")
			}
		})
	}
}
func TestGuidedSenderRejectsMissingFilesAndBinding(t *testing.T) {
	for _, missing := range []string{"state.json", "state.lock"} {
		t.Run(missing, func(t *testing.T) {
			f := integrationFixture(t, "tls", nil)
			cfg := f.material.config
			cfg.SchemaVersion = GuidedConfigVersion
			if e := InitializeGuidedState(cfg); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(filepath.Join(cfg.StateDirectory, missing), filepath.Join(t.TempDir(), missing)); e != nil {
				t.Fatal(e)
			}
			before, _ := os.ReadDir(cfg.StateDirectory)
			if e := ValidateGuidedState(cfg); !errors.Is(e, ErrState) {
				t.Fatal("lost ledger component was adopted")
			}
			after, _ := os.ReadDir(cfg.StateDirectory)
			if len(before) != len(after) {
				t.Fatal("rejected missing file recreated")
			}
		})
	}
	f := integrationFixture(t, "tls", nil)
	cfg := f.material.config
	cfg.SchemaVersion = GuidedConfigVersion
	if e := InitializeGuidedState(cfg); e != nil {
		t.Fatal(e)
	}
	changed := cfg
	changed.AgentID = "agent_" + strings.Repeat("f", 32)
	if e := ValidateGuidedState(changed); !errors.Is(e, ErrState) {
		t.Fatal("wrong identity binding accepted")
	}
	legacy := cfg
	legacy.SchemaVersion = ConfigVersion
	m, e := loadConfig(legacy)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Run(context.Background(), m); !errors.Is(e, ErrState) {
		t.Fatal("manual-v1 silently adopted guided-v2 state")
	}
}
