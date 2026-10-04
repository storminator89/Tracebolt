//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operational"
	"localrmm/internal/signedhttp"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func operationsConfig(c Config) Config {
	c.SchemaVersion = OperationalConfigVersion
	c.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
	return c
}
func unavailableOperations(_ context.Context, now time.Time) operational.Snapshot {
	return operational.Empty(now, operational.ReasonPermissionDenied)
}

func TestOperationalConfigAndLedgerIsolation(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f := integrationFixture(t, transport, nil)
			basic := f.material.config
			basic.SchemaVersion = GuidedConfigVersion
			c := operationsConfig(basic)
			for _, version := range []string{ConfigVersion, GuidedConfigVersion} {
				bad := c
				bad.SchemaVersion = version
				if bad.Validate() == nil {
					t.Fatal("old version enabled operations")
				}
			}
			for _, profile := range []string{"", enrollmentcrypto.CollectionProfile, "managed-operations-v2"} {
				bad := c
				bad.CollectionProfile = profile
				if bad.Validate() == nil {
					t.Fatal("v3 accepted wrong profile")
				}
			}
			if InitializeGuidedState(basic) != nil {
				t.Fatal("basic initialization")
			}
			original, _ := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if InitializeGuidedState(c) == nil || ValidateGuidedState(c) == nil {
				t.Fatal("operational adopted basic ledger")
			}
			after, _ := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
			if !bytes.Equal(original, after) {
				t.Fatal("ledger changed")
			}
			c.StateDirectory = filepath.Join(filepath.Dir(c.StateDirectory), "operations")
			m, err := loadConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Run(context.Background(), m); !errors.Is(err, ErrState) {
				t.Fatal("v3 created missing ledger")
			}
			if _, err := os.Stat(c.StateDirectory); !os.IsNotExist(err) {
				t.Fatal("v3 created state path")
			}
			if InitializeGuidedState(c) != nil || ValidateGuidedState(c) != nil {
				t.Fatal("fresh v3 initialization")
			}
			basic.StateDirectory = c.StateDirectory
			if ValidateGuidedState(basic) == nil || InitializeGuidedState(basic) == nil {
				t.Fatal("basic adopted operational ledger")
			}
		})
	}
}

func TestOperationalSenderExactRetryAndSignature(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			var mu sync.Mutex
			var bodies [][]byte
			var verifier *signedhttp.Verifier
			var agentID string
			f := integrationFixture(t, transport, func(_ http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var raw []byte
					var signedAt time.Time
					var signedSequence uint64
					if transport == "http-test" {
						v, err := verifier.Verify(r)
						if err != nil {
							t.Error("signed operational bytes rejected")
							w.WriteHeader(401)
							return
						}
						raw = v.Body
						signedAt, signedSequence = v.SignedAt, v.Sequence
					} else {
						raw, _ = io.ReadAll(io.LimitReader(r.Body, MaxFrameBytes+1))
						if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
							t.Error("missing client certificate")
						}
					}
					var frame frame
					if json.Unmarshal(raw, &frame) != nil || frame.SchemaVersion != FrameOperationalVersion || frame.Operational == nil {
						t.Error("missing operational frame")
						w.WriteHeader(400)
						return
					}
					if transport == "http-test" && (!signedAt.Equal(frame.Observation.GeneratedAt) || signedSequence != frame.Sequence) {
						t.Error("raw signature metadata mismatch")
						w.WriteHeader(400)
						return
					}
					mu.Lock()
					bodies = append(bodies, bytes.Clone(raw))
					first := len(bodies) == 1
					mu.Unlock()
					if first {
						w.WriteHeader(503)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: agentID, Sequence: frame.Sequence, CollectedAt: frame.Observation.Observation.LastSeen, ReceivedAt: time.Now().UTC(), Duplicate: true})
				})
			})
			agentID = f.material.config.AgentID
			if transport == "http-test" {
				var err error
				verifier, err = signedhttp.New(signedhttp.Config{Origin: f.material.config.ManagerOrigin, Registry: f.registry})
				if err != nil {
					t.Fatal("verifier fixture")
				}
			}
			c := operationsConfig(f.material.config)
			if InitializeGuidedState(c) != nil {
				t.Fatal("initialize")
			}
			m, err := loadConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			state, err := openSenderState(m)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			calls := 0
			collect := func(ctx context.Context, at time.Time) operational.Snapshot {
				calls++
				return unavailableOperations(ctx, at)
			}
			report, err := runUsingStateWithCollector(context.Background(), m, state, collect)
			if !errors.Is(err, ErrTransport) || report.Sequence != 1 {
				t.Fatal("first pending not retained")
			}
			pending, _ := state.Pending()
			before := pending.Body()
			report, err = runUsingStateWithCollector(context.Background(), m, state, collect)
			if err != nil || !report.RetriedPending || !report.Duplicate || calls != 1 {
				t.Fatal("retry recollected or failed")
			}
			mu.Lock()
			equal := len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1]) && bytes.Equal(before, bodies[0])
			mu.Unlock()
			if !equal {
				t.Fatal("operational retry mutated exact bytes")
			}
			decoded, err := decodeFrameForConfig(before, 1, c)
			if err != nil || decoded.Operational.Sections.Events.Meta.Quality != operational.Denied || !decoded.Operational.Sections.Events.Meta.ObservedAt.Equal(decoded.Operational.CollectedAt) {
				t.Fatal("unavailable metadata changed")
			}
			if _, err := decodeFrame(before, 1); err == nil {
				t.Fatal("basic decoder accepted operational pending")
			}
		})
	}
}

func TestOperationalCancellationAndInvalidCollectionNeverStage(t *testing.T) {
	for _, scenario := range []string{"cancel", "invalid", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			f := integrationFixture(t, "http-test", func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
			})
			c := operationsConfig(f.material.config)
			if InitializeGuidedState(c) != nil {
				t.Fatal("initialize")
			}
			m, _ := loadConfig(c)
			state, err := openSenderState(m)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err = runUsingStateWithCollector(ctx, m, state, func(ctx context.Context, at time.Time) operational.Snapshot {
				snapshot := unavailableOperations(ctx, at)
				switch scenario {
				case "cancel":
					cancel()
				case "invalid":
					snapshot.Sections.Events.Meta.GenerationID = "sample_" + strings.Repeat("0", 32)
				case "oversized":
					snapshot.Sections.Software.Items = []operational.Software{{Name: strings.Repeat("x", MaxFrameBytes)}}
				}
				return snapshot
			})
			if err == nil {
				t.Fatal("invalid or canceled collection accepted")
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost")
			}
			pending, _ := state.Pending()
			next, _ := state.NextSequence()
			if pending != nil || next != 1 || requests.Load() != 0 {
				t.Fatal("collection failure staged or sent")
			}
		})
	}
}

func TestFrameShapeAndCollectionIsolation(t *testing.T) {
	basic := Config{SchemaVersion: GuidedConfigVersion}
	c := operationsConfig(basic)
	_, raw, err := collectFrame(context.Background(), basic, 1, func(context.Context, time.Time) operational.Snapshot {
		t.Fatal("basic invoked operational collector")
		return operational.Snapshot{}
	})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if len(fields) != 3 || fields["operational"] != nil {
		t.Fatal("basic frame expanded")
	}
	if _, err := decodeFrameForConfig(raw, 1, c); err == nil {
		t.Fatal("v3 accepted basic pending")
	}
	_, raw, err = collectFrame(context.Background(), c, 1, unavailableOperations)
	if err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Replace(raw, []byte(`"operational":{`), append([]byte(`"operational":{`), bytes.Repeat([]byte(" "), operational.MaxSnapshotBytes)...), 1)
	if _, err := decodeFrameForConfig(oversized, 1, c); err == nil {
		t.Fatal("oversized raw snapshot accepted")
	}
	for name, alter := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"durationMs":0`), []byte(`"durationMs":0,"durationMs":0`), 1)
		},
		"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"durationMs":0,`), nil, 1) },
		"null":    func(b []byte) []byte { return bytes.Replace(b, []byte(`"items":[]`), []byte(`"items":null`), 1) },
		"unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"durationMs":0`), []byte(`"durationMs":0,"extra":true`), 1)
		},
	} {
		if _, err := decodeFrameForConfig(alter(bytes.Clone(raw)), 1, c); err == nil {
			t.Fatal("invalid operational JSON accepted", name)
		}
	}
	var f frame
	json.Unmarshal(raw, &f)
	f.Observation.GeneratedAt = f.Operational.CollectedAt.Add(-time.Second)
	future, _ := json.Marshal(f)
	if _, err := decodeFrameForConfig(future, 1, c); err == nil {
		t.Fatal("future operational start accepted")
	}
}

func TestOperationalSequenceCeilingBeforeCollectionAndPending(t *testing.T) {
	c := operationsConfig(Config{})
	calls := 0
	collect := func(ctx context.Context, at time.Time) operational.Snapshot {
		calls++
		return unavailableOperations(ctx, at)
	}
	if _, _, err := collectFrame(context.Background(), c, operational.MaxSafeInteger+1, collect); !errors.Is(err, ErrState) || calls != 0 {
		t.Fatal("exhausted v3 sequence collected")
	}
	f, raw, err := collectFrame(context.Background(), c, operational.MaxSafeInteger, collect)
	if err != nil {
		t.Fatal("maximum safe sequence rejected")
	}
	if _, err := decodeFrameForConfig(raw, operational.MaxSafeInteger, c); err != nil {
		t.Fatal("maximum safe pending rejected")
	}
	f.Sequence++
	raw, _ = json.Marshal(f)
	if _, err := decodeFrameForConfig(raw, f.Sequence, c); err == nil {
		t.Fatal("oversized pending sequence accepted")
	}
	// The original schema retains its existing signed-64-bit sequence range.
	f.SchemaVersion = FrameVersion
	f.Operational = nil
	raw, _ = json.Marshal(f)
	if _, err := decodeFrame(raw, f.Sequence); err != nil {
		t.Fatal("v1 sequence range changed")
	}
}

func TestPendingWrongCollectionSchemaIsRetainedWithoutFallback(t *testing.T) {
	for _, version := range []string{GuidedConfigVersion, OperationalConfigVersion} {
		t.Run(version, func(t *testing.T) {
			var requests atomic.Int32
			f := integrationFixture(t, "http-test", func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
			})
			c := f.material.config
			c.SchemaVersion = version
			other := operationsConfig(c)
			if version == OperationalConfigVersion {
				c = other
				other.SchemaVersion = GuidedConfigVersion
				other.CollectionProfile = ""
			}
			if InitializeGuidedState(c) != nil {
				t.Fatal("initialize")
			}
			m, err := loadConfig(c)
			if err != nil {
				t.Fatal(err)
			}
			state, err := openSenderState(m)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			_, raw, err := collectFrame(context.Background(), other, 1, unavailableOperations)
			if err != nil {
				t.Fatal("pending fixture")
			}
			original, err := state.Stage(1, raw)
			if err != nil {
				t.Fatal("stage fixture")
			}
			_, err = runUsingStateWithCollector(context.Background(), m, state, func(context.Context, time.Time) operational.Snapshot {
				t.Error("schema mismatch fell back to collection")
				return operational.Snapshot{}
			})
			if !errors.Is(err, ErrState) {
				t.Fatal("wrong-profile pending accepted")
			}
			retained, err := state.Pending()
			if err != nil || retained == nil || retained.Digest != original.Digest || !bytes.Equal(retained.Body(), raw) || requests.Load() != 0 {
				t.Fatal("wrong-profile pending changed or sent")
			}
		})
	}
}
