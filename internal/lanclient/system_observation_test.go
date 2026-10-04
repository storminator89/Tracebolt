//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemstate"
	"localrmm/internal/systemwire"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSystemNativeTLSHTTPExactRetryBeforeRecapture(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			var verifier *systemwire.Verifier
			var agent string
			var mu sync.Mutex
			var bodies [][]byte
			var committed []byte
			f := integrationFixture(t, profile, func(_ http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var raw []byte
					var err error
					if profile == "http-test" {
						v, e := verifier.Verify(r)
						err = e
						raw = v.Body
					} else {
						raw, err = io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
						if r.TLS == nil {
							t.Error("missing real TLS")
						}
					}
					frame, e := systemwire.Decode(raw)
					if err != nil || e != nil || r.URL.Path != systemwire.Path {
						t.Error("invalid system request")
						w.WriteHeader(400)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					bodies = append(bodies, bytes.Clone(raw))
					if committed == nil {
						sum := sha256.Sum256(raw)
						committed, _ = json.Marshal(systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: agent, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: frame.Snapshot.CollectedAt, ReceivedAt: time.Now().UTC(), BodyHash: hex.EncodeToString(sum[:])})
						w.WriteHeader(503)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(committed)
				})
			})
			agent = f.material.config.AgentID
			var e error
			if profile == "http-test" {
				verifier, e = systemwire.New(systemwire.Config{Origin: f.material.config.ManagerOrigin, Registry: f.registry})
				if e != nil {
					t.Fatal(e)
				}
			}
			c := completeConfig(f.material.config)
			if InitializeGuidedState(c) != nil {
				t.Fatal("complete fixture init")
			}
			m, e := loadConfig(c)
			if e != nil {
				t.Fatal(e)
			}
			var captures atomic.Int32
			source := func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
				captures.Add(1)
				return systeminventory.Empty(id, at, systeminventory.ReasonPermissionDenied), nil
			}
			sender, e := openSystemSenderWithSource(m, source, func() time.Time { return time.Now().UTC() })
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first, e := sender.Run(ctx)
			if !errors.Is(e, ErrSystemTransport) || first.Sequence != 1 {
				t.Fatal("uncertain response was not retained", e)
			}
			pending, _ := sender.state.Pending()
			expected := pending.Body()
			sender.Close()
			sender, e = openSystemSenderWithSource(m, source, func() time.Time { return time.Now().UTC() })
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			retried, e := sender.Run(ctx)
			if e != nil || !retried.RetriedPending || retried.Sequence != 1 || retried.Status != "acknowledged" || captures.Load() != 1 {
				t.Fatal("retry recollected or failed", e)
			}
			mu.Lock()
			same := len(bodies) == 2 && bytes.Equal(bodies[0], bodies[1]) && bytes.Equal(expected, bodies[0])
			mu.Unlock()
			if !same {
				t.Fatal("retry changed exact bytes")
			}
		})
	}
}

func TestSystemNativeMissingStateAndFuturePendingFailBeforeSource(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	c := completeConfig(f.material.config)
	m, e := loadConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	source := func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		calls++
		return systeminventory.Empty(id, at, systeminventory.ReasonSourceMissing), nil
	}
	now := time.Now().UTC()
	if _, e = openSystemSenderWithSource(m, source, func() time.Time { return now }); !errors.Is(e, ErrState) {
		t.Fatal("missing state adopted")
	}
	if InitializeGuidedState(c) != nil {
		t.Fatal("initialize")
	}
	state, e := systemstate.OpenExisting(systemStateDirectory(c), systemStateBinding(m))
	if e != nil {
		t.Fatal(e)
	}
	generation, _ := systemwire.GenerationID(c.AgentID, 1)
	raw, _ := systemwire.Encode(1, systeminventory.Empty(generation, now.Add(time.Minute), systeminventory.ReasonSourceMissing))
	pending, e := state.Stage(1, raw)
	if e != nil {
		t.Fatal(e)
	}
	state.Close()
	sender, e := openSystemSenderWithSource(m, source, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	if _, e = sender.Run(context.Background()); !errors.Is(e, ErrSystemTransport) || calls != 0 {
		t.Fatal("clock rollback recollected", e)
	}
	after, e := sender.state.Pending()
	if e != nil || after == nil || after.Digest != pending.Digest || !bytes.Equal(after.Body(), raw) {
		t.Fatal("future pending changed")
	}
}
