//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
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

func packagesConfig(c Config) Config {
	c.SchemaVersion = PackageConfigVersion
	c.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	return c
}
func unavailablePackages(_ context.Context, generation string, at time.Time) (linuxpackages.Snapshot, error) {
	return linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Inventory: linuxpackages.Inventory{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied, Items: []linuxpackages.PackageRow{}}}, nil
}

func TestPackageSenderExactRetryAndSignature(t *testing.T) {
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
					if json.Unmarshal(raw, &frame) != nil || frame.SchemaVersion != FramePackagesVersion || frame.Operational == nil || frame.Packages == nil {
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
			c := packagesConfig(f.material.config)
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
			packageCalls := 0
			basicCalls := 0
			basicCollect := func() model.Device { basicCalls++; return syntheticPackageBasic() }
			packageCollect := func(ctx context.Context, generation string, at time.Time) (linuxpackages.Snapshot, error) {
				packageCalls++
				return unavailablePackages(ctx, generation, at)
			}
			collect := func(ctx context.Context, at time.Time) operational.Snapshot {
				calls++
				return unavailableOperations(ctx, at)
			}
			report, err := runUsingStateWithSources(context.Background(), m, state, collect, packageCollect, basicCollect)
			if !errors.Is(err, ErrTransport) || report.Sequence != 1 {
				t.Fatal("first pending not retained")
			}
			pending, _ := state.Pending()
			before := pending.Body()
			report, err = runUsingStateWithSources(context.Background(), m, state, collect, packageCollect, basicCollect)
			if err != nil || !report.RetriedPending || !report.Duplicate || calls != 1 || packageCalls != 1 || basicCalls != 1 {
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
			if _, err := lanstore.ValidateFrame(before, time.Now().UTC()); err != nil {
				t.Fatal("server rejects staged frame", err)
			}
			if _, err := decodeFrame(before, 1); err == nil {
				t.Fatal("basic decoder accepted operational pending")
			}
		})
	}
}

func TestPackageConfigAndEveryOlderLedgerDomain(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, version := range []string{ConfigVersion, GuidedConfigVersion, OperationalConfigVersion} {
			t.Run(transport+"/"+version, func(t *testing.T) {
				f := integrationFixture(t, transport, nil)
				old := f.material.config
				old.SchemaVersion = version
				if version == OperationalConfigVersion {
					old = operationsConfig(old)
				}
				m, err := loadConfig(old)
				if err != nil {
					t.Fatal(err)
				}
				if old.guided() && InitializeGuidedState(old) != nil {
					t.Fatal("initialize older state")
				}
				state, err := openSenderState(m)
				if err != nil {
					t.Fatal(err)
				}
				state.Close()
				c := packagesConfig(old)
				original, _ := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
				if InitializeGuidedState(c) == nil || ValidateGuidedState(c) == nil {
					t.Fatal("packages adopted older ledger")
				}
				m, err = loadConfig(c)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Run(context.Background(), m); !errors.Is(err, ErrState) {
					t.Fatal("Run adopted old ledger")
				}
				after, _ := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
				if !bytes.Equal(original, after) {
					t.Fatal("old ledger mutated")
				}
				c.StateDirectory += "-packages"
				m, _ = loadConfig(c)
				if _, err := Run(context.Background(), m); !errors.Is(err, ErrState) {
					t.Fatal("missing ledger accepted")
				}
				if _, err := os.Stat(c.StateDirectory); !os.IsNotExist(err) {
					t.Fatal("Run created package ledger")
				}
				if InitializeGuidedState(c) != nil || ValidateGuidedState(c) != nil {
					t.Fatal("fresh package ledger rejected")
				}
				old.StateDirectory = c.StateDirectory
				m, err = loadConfig(old)
				if err != nil {
					t.Fatal(err)
				}
				if state, err := openSenderState(m); err == nil {
					state.Close()
					t.Fatal("old profile adopted package ledger")
				}
				for _, profile := range []string{"", enrollmentcrypto.CollectionProfile, operational.CollectionProfile, "managed-operations-v3"} {
					bad := c
					bad.CollectionProfile = profile
					if bad.Validate() == nil {
						t.Fatal("v4 accepted another profile")
					}
				}
				for _, older := range []string{ConfigVersion, GuidedConfigVersion, OperationalConfigVersion} {
					bad := c
					bad.SchemaVersion = older
					if bad.Validate() == nil {
						t.Fatal("older version accepted package profile")
					}
				}
			})
		}
	}
}

func TestPackageCollectorFailuresNeverStage(t *testing.T) {
	for _, scenario := range []string{"cancel", "error", "invalid", "generation", "time", "oversized", "operations-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			f := integrationFixture(t, "http-test", func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
			})
			c := packagesConfig(f.material.config)
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			_, err = runUsingStateWithPackageFixtures(ctx, m, state, func(ctx context.Context, at time.Time) operational.Snapshot {
				s := unavailableOperations(ctx, at)
				if scenario == "operations-invalid" {
					s.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
				}
				return s
			}, func(ctx context.Context, generation string, at time.Time) (linuxpackages.Snapshot, error) {
				calls++
				s, _ := unavailablePackages(ctx, generation, at)
				switch scenario {
				case "cancel":
					cancel()
				case "error":
					return s, errors.New("inert fixture failure")
				case "invalid":
					s.Inventory.Items = nil
				case "generation":
					s.GenerationID = "sample_" + strings.Repeat("0", 32)
				case "time":
					s.CollectedAt = at.Add(-time.Nanosecond)
				case "oversized":
					s.Inventory.Items = []linuxpackages.PackageRow{{Name: strings.Repeat("x", MaxFrameBytes)}}
				}
				return s, nil
			})
			if err == nil || scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("failed collection accepted or cancellation lost")
			}
			if scenario == "operations-invalid" && calls != 0 {
				t.Fatal("package collector ran after invalid operations")
			}
			pending, _ := state.Pending()
			next, _ := state.NextSequence()
			if pending != nil || next != 1 || requests.Load() != 0 {
				t.Fatal("failed collection staged or sent")
			}
		})
	}
}

func TestPackageFrameTrimsOnlyCloneAndKeepsOlderLimits(t *testing.T) {
	var original operational.Snapshot
	collect := func(ctx context.Context, at time.Time) operational.Snapshot {
		s := unavailableOperations(ctx, at)
		v := &s.Sections.Software
		v.Meta.Quality, v.Meta.Reason, v.Meta.Complete, v.Meta.CountExact, v.Meta.ObservedCount = operational.Healthy, operational.ReasonNone, true, true, 160
		for i := range 160 {
			v.Items = append(v.Items, operational.Software{Name: fmt.Sprintf("package-%03d", i), Version: "1." + strings.Repeat("1", 170), Architecture: "amd64", Manager: "dpkg"})
		}
		original = s
		return s
	}
	f, raw, err := collectFrameWithPackageFixtures(context.Background(), packagesConfig(Config{}), 1, collect, unavailablePackages)
	if err != nil {
		t.Fatal(err)
	}
	op, _ := json.Marshal(f.Operational)
	before, _ := json.Marshal(original)
	if len(op) > operational.MaxPackageFrameSnapshotBytes || len(before) <= operational.MaxPackageFrameSnapshotBytes || len(original.Sections.Software.Items) != 160 || !original.Sections.Software.Meta.Complete {
		t.Fatal("reservation changed original or failed")
	}
	if f.Operational.CollectionProfile != operational.CollectionProfile || f.Operational.GenerationID != original.GenerationID || !f.Operational.CollectedAt.Equal(original.CollectedAt) || !f.Packages.CollectedAt.Equal(original.CollectedAt) || f.Packages.GenerationID != original.GenerationID || f.Operational.Sections.Software.Meta.ObservedCount != 160 || !f.Operational.Sections.Software.Meta.Truncated {
		t.Fatal("capture/count provenance changed")
	}
	if _, err := lanstore.ValidateFrame(raw, time.Now().UTC()); err != nil {
		t.Fatal("server rejected bounded frame", err)
	}
	older, _, err := collectFrameWithPackageFixtures(context.Background(), operationsConfig(Config{}), 1, collect, func(context.Context, string, time.Time) (linuxpackages.Snapshot, error) {
		t.Fatal("older profile invoked packages")
		return linuxpackages.Snapshot{}, nil
	})
	if err != nil || len(older.Operational.Sections.Software.Items) != 160 || !older.Operational.Sections.Software.Meta.Complete {
		t.Fatal("old 48 KiB allowance changed", err)
	}
	calls := 0
	if _, _, err := collectFrameWithPackageFixtures(context.Background(), packagesConfig(Config{}), operational.MaxSafeInteger+1, func(context.Context, time.Time) operational.Snapshot { calls++; return operational.Snapshot{} }, unavailablePackages); !errors.Is(err, ErrState) || calls != 0 {
		t.Fatal("sequence ceiling crossed before collection")
	}
}

func TestPackagePendingStrictShapeAndWrongSchemaRetained(t *testing.T) {
	c := packagesConfig(Config{})
	f, raw, err := collectFrameWithPackageFixtures(context.Background(), c, 1, unavailableOperations, unavailablePackages)
	if err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func([]byte) []byte{
		"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg",`), nil, 1) },
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg"`), []byte(`"scope":"agent-visible-dpkg","scope":"agent-visible-dpkg"`), 1)
		},
		"unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg"`), []byte(`"scope":"agent-visible-dpkg","trusted":true`), 1)
		},
		"null": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"installedCount":null`), []byte(`"installedCount":"0"`), 1)
		},
		"basic-missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"synthetic":false,`), nil, 1) },
	} {
		bad := alter(bytes.Clone(raw))
		if bytes.Equal(bad, raw) {
			t.Fatal("ineffective fixture", name)
		}
		if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
			t.Fatal("invalid pending accepted", name)
		}
	}
	for _, version := range []string{ConfigVersion, GuidedConfigVersion, OperationalConfigVersion} {
		older := Config{SchemaVersion: version}
		if version == OperationalConfigVersion {
			older = operationsConfig(older)
		}
		if _, err := decodeFrameForConfig(raw, 1, older); err == nil {
			t.Fatal("old sender accepted packages")
		}
	}
	f.Packages.GenerationID = "sample_" + strings.Repeat("0", 32)
	bad, _ := json.Marshal(f)
	if _, err := decodeFrameForConfig(bad, 1, c); err == nil {
		t.Fatal("mismatched pending accepted")
	}
	fixture := integrationFixture(t, "http-test", nil)
	c = packagesConfig(fixture.material.config)
	if InitializeGuidedState(c) != nil {
		t.Fatal("initialize")
	}
	m, _ := loadConfig(c)
	state, err := openSenderState(m)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	_, old, err := collectFrameWithPackageFixtures(context.Background(), operationsConfig(c), 1, unavailableOperations, unavailablePackages)
	if err != nil {
		t.Fatal(err)
	}
	p, err := state.Stage(1, old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runUsingStateWithPackageFixtures(context.Background(), m, state, func(context.Context, time.Time) operational.Snapshot {
		t.Fatal("mismatch recollected")
		return operational.Snapshot{}
	}, func(context.Context, string, time.Time) (linuxpackages.Snapshot, error) {
		t.Fatal("mismatch recollected packages")
		return linuxpackages.Snapshot{}, nil
	})
	if !errors.Is(err, ErrState) {
		t.Fatal("older pending accepted")
	}
	after, _ := state.Pending()
	if after == nil || after.Digest != p.Digest || !bytes.Equal(after.Body(), old) {
		t.Fatal("wrong-profile pending mutated")
	}
}

func TestPackageExpiredPendingDiscardsWithoutReusingSequence(t *testing.T) {
	fixture := integrationFixture(t, "http-test", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	})
	c := packagesConfig(fixture.material.config)
	if InitializeGuidedState(c) != nil {
		t.Fatal("initialize")
	}
	m, _ := loadConfig(c)
	state, err := openSenderState(m)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f, _, err := collectFrameWithPackageFixtures(context.Background(), c, 1, unavailableOperations, unavailablePackages)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-10 * time.Minute)
	f.Observation.GeneratedAt = old
	f.Observation.Observation.LastSeen = old
	f.Observation.Observation.CPU.CollectedAt = old
	f.Observation.Observation.Memory.CollectedAt = old
	f.Observation.Observation.Disk.CollectedAt = old
	for i := range f.Observation.Observation.Evidence {
		f.Observation.Observation.Evidence[i].CollectedAt = old
	}
	op := operational.Empty(old, operational.ReasonPermissionDenied)
	f.Operational = &op
	p, _ := unavailablePackages(context.Background(), op.GenerationID, old)
	f.Packages = &p
	raw, _ := json.Marshal(f)
	if _, err := state.Stage(1, raw); err != nil {
		t.Fatal(err)
	}
	calls := 0
	report, err := runUsingStateWithPackageFixtures(context.Background(), m, state, unavailableOperations, func(ctx context.Context, generation string, at time.Time) (linuxpackages.Snapshot, error) {
		calls++
		return unavailablePackages(ctx, generation, at)
	})
	if !errors.Is(err, ErrTransport) || !report.DiscardedStale || report.RetriedPending || report.Sequence != 2 || calls != 1 {
		t.Fatal("expired pending reuse or missing replacement", err)
	}
	pending, _ := state.Pending()
	next, _ := state.NextSequence()
	if pending == nil || pending.Sequence != 2 || next != 3 || bytes.Equal(raw, pending.Body()) {
		t.Fatal("expired sequence not consumed")
	}
}

func TestPackagePendingRawReservationsAndCanonicalBasicCap(t *testing.T) {
	c := packagesConfig(Config{})
	f, raw, err := collectFrameWithPackageFixtures(context.Background(), c, 1, unavailableOperations, unavailablePackages)
	if err != nil {
		t.Fatal(err)
	}
	for name, cap := range map[string]int{"observation": MaxPackageObservationBytes, "operational": operational.MaxPackageFrameSnapshotBytes, "packages": linuxpackages.MaxSnapshotBytes} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("fixture")
		}
		needle := []byte(`"` + name + `":{`)
		padded := bytes.Replace(raw, needle, append(bytes.Clone(needle), bytes.Repeat([]byte(" "), cap-len(fields[name]))...), 1)
		if _, err := decodeFrameForConfig(padded, 1, c); err != nil {
			t.Fatal("exact raw cap rejected", name, err)
		}
		oversized := bytes.Replace(padded, needle, append(bytes.Clone(needle), ' '), 1)
		if _, err := decodeFrameForConfig(oversized, 1, c); err == nil {
			t.Fatal("raw cap overflow accepted", name)
		}
	}
	f.Observation.Privacy = []string{strings.Repeat("<", 3000)}
	canonical, _ := json.Marshal(f)
	compact := bytes.ReplaceAll(canonical, []byte(`\u003c`), []byte("<"))
	if _, err := decodeFrameForConfig(compact, 1, c); err == nil {
		t.Fatal("canonical basic overflow accepted")
	}
	for _, replacement := range []string{`"version":"\ud800"`, `"version":"` + strings.Repeat("a", 4097) + `"`} {
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		var observation map[string]json.RawMessage
		json.Unmarshal(fields["observation"], &observation)
		needle := append([]byte(`"version":`), observation["version"]...)
		invalid := bytes.Replace(raw, needle, []byte(replacement), 1)
		if _, err := decodeFrameForConfig(invalid, 1, c); err == nil {
			t.Fatal("invalid decoded JSON string accepted")
		}
	}
}

// These fixtures never invoke basic, operational or package production sources.
// The fixed collector-role labels satisfy the wire policy; all values are inert.
func syntheticPackageBasic() model.Device {
	at := time.Now().UTC()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Inert fixture", CollectedAt: at}
	return model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture OS", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
}

func runUsingStateWithPackageFixtures(ctx context.Context, m Material, state *lanclientstate.State, operations func(context.Context, time.Time) operational.Snapshot, packages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (Report, error) {
	return runUsingStateWithSources(ctx, m, state, operations, packages, syntheticPackageBasic)
}

func collectFrameWithPackageFixtures(ctx context.Context, c Config, sequence uint64, operations func(context.Context, time.Time) operational.Snapshot, packages func(context.Context, string, time.Time) (linuxpackages.Snapshot, error)) (frame, []byte, error) {
	return collectFrameWithSources(ctx, c, sequence, operations, packages, syntheticPackageBasic)
}
