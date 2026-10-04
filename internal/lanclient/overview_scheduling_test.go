//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/overviewstate"
	"localrmm/internal/overviewwire"
	"net/http"
	"testing"
	"time"
)

func TestOverviewFailureKeepsNormalForegroundMetricsAndJournalProgress(t *testing.T) {
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			// Only the complete overview source and protocol are exercised; ordinary
			// metrics and journal stages are fixture callbacks, never production readers.
			sender, h, captures := overviewFixture(t, "tls", 1, 1)
			h.override = func(w http.ResponseWriter, _ overviewwire.Message, _, _ []byte) bool {
				w.WriteHeader(code)
				return true
			}
			clock := &instantClock{at: h.clock.now()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			metrics, journals, finished := 0, 0, 0
			metricTimes := []time.Time{}
			summary, err := agentloop.Run(ctx, agentloop.Config{Interval: 30 * time.Second}, agentloop.Dependencies{
				Clock: clock, Random: func(int64) int64 { return 0 },
				Attempt: func(parent context.Context) agentloop.Result {
					metrics++
					metricTimes = append(metricTimes, clock.Now())
					h.clock.set(clock.Now())
					report := Report{Status: "acknowledged", Sequence: uint64(metrics)}
					e := runOverviewAndJournal(parent, sender, &report, func(context.Context) string { journals++; return "idle" })
					if e != nil {
						t.Error("overview-only failure changed metric outcome", e)
						return agentloop.Result{Outcome: agentloop.Retryable}
					}
					return agentloop.Result{Outcome: agentloop.Success, Metadata: agentloop.Metadata{Sequence: report.Sequence, JournalStatus: report.JournalStatus, ProcessesStatus: report.ProcessesStatus, ProcessesSequence: report.ProcessesSequence, VolumesStatus: report.VolumesStatus, VolumesSequence: report.VolumesSequence, OverviewOperations: report.OverviewOperations}}
				},
				Observe: func(event agentloop.Event) error {
					if event.Phase == agentloop.Finished {
						finished++
						if event.Outcome != agentloop.Success || event.ConsecutiveFailures != 0 || event.Metadata.JournalStatus != "idle" || event.Metadata.ProcessesStatus != "pending_retained" || event.Metadata.VolumesStatus != "pending_retained" || event.Metadata.Sequence != uint64(finished) {
							t.Error("overview failure altered successful foreground report")
						}
						if finished == 3 {
							cancel()
						}
					}
					return nil
				},
			})
			if !errors.Is(err, context.Canceled) || summary.Attempts != 3 || metrics != 3 || journals != 3 || captures.Load() != 1 {
				t.Fatal("metric/journal progression or retry capture changed", err, summary, metrics, journals, captures.Load())
			}
			if len(clock.waits) != 2 || clock.waits[0] != 30*time.Second || clock.waits[1] != 30*time.Second || metricTimes[1].Sub(metricTimes[0]) != 30*time.Second || metricTimes[2].Sub(metricTimes[1]) != 30*time.Second {
				t.Fatal("overview failure backed off metrics")
			}
			// The same sequence/body is retained through repeated failed sends; the
			// normal metric cadence is not achieved by dropping or refreshing overview.
			original := map[string][]byte{}
			for _, request := range h.requests {
				if request.message.Operation != "begin" || request.message.Sequence != 1 {
					t.Fatal("pending overview advanced")
				}
				if prior, ok := original[request.message.Section]; ok {
					if !bytes.Equal(prior, request.body) {
						t.Fatal("overview bytes refreshed")
					}
				} else {
					original[request.message.Section] = request.body
				}
			}
		})
	}
}
func TestOverviewSchedulingIsolationPreservesTrustedFatalErrors(t *testing.T) {
	parent := context.Background()
	for _, err := range []error{nil, ErrOverviewPending, ErrOverviewTransport, ErrOverviewReceipt, ErrOverviewConflict, errOverviewDisabled, context.DeadlineExceeded} {
		if e := overviewSchedulingError(parent, err); e != nil {
			t.Fatal("extension failure escaped scheduling isolation", e)
		}
	}
	unexpected := errors.New("unexpected trusted boundary failure")
	for _, err := range []error{ErrState, ErrConfiguration, context.Canceled, unexpected, errors.Join(ErrState, ErrOverviewTransport), errors.Join(agentloop.ErrRevoked, ErrOverviewTransport)} {
		if e := overviewSchedulingError(parent, err); !errors.Is(e, err) {
			t.Fatal("fatal error masked", err, e)
		}
	}
	canceled, cancel := context.WithCancel(parent)
	cancel()
	for _, err := range []error{nil, ErrOverviewTransport, context.DeadlineExceeded} {
		if e := overviewSchedulingError(canceled, err); !errors.Is(e, context.Canceled) {
			t.Fatal("parent cancellation masked", e)
		}
	}
	expired, stop := context.WithDeadline(parent, time.Now().Add(-time.Second))
	defer stop()
	if e := overviewSchedulingError(expired, ErrOverviewTransport); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("parent deadline masked", e)
	}
}
func TestOverviewTrustedFailureStillStopsJournalCompletion(t *testing.T) {
	sender, _, _ := overviewFixture(t, "tls", 0, 0)
	sender.Close()
	report := Report{}
	journalCalls := 0
	e := runOverviewAndJournal(context.Background(), sender, &report, func(context.Context) string { journalCalls++; return "idle" })
	if !errors.Is(e, ErrState) || journalCalls != 0 {
		t.Fatal("trusted invalid state allowed continuation", e, journalCalls)
	}
	// An absent/default-off extension still advances the existing journal stage.
	if e = runOverviewAndJournal(context.Background(), nil, &report, func(context.Context) string { journalCalls++; return "idle" }); e != nil || journalCalls != 1 {
		t.Fatal("default-off behavior changed", e)
	}
}

func TestOverviewSiblingFatalFailureCannotBeMaskedByDeliveryFailure(t *testing.T) {
	sender, h, _ := overviewFixture(t, "tls", 1, 1)
	h.override = func(w http.ResponseWriter, m overviewwire.Message, _, _ []byte) bool {
		if m.Section == "processes" {
			sender.volumes.state.Close()
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	}
	report := Report{}
	journals := 0
	err := runOverviewAndJournal(context.Background(), sender, &report, func(context.Context) string { journals++; return "idle" })
	if !errors.Is(err, ErrState) || journals != 0 {
		t.Fatal("trusted sibling state failure was hidden", err, journals)
	}
	if report.ProcessesStatus != "pending_retained" || report.VolumesStatus != "pending_retained" {
		t.Fatal("fixed pending metadata lost")
	}
}

// Expiration is injected without sleeping or waiting for a real source call.
type overviewExpiredContext struct{ context.Context }

func (c overviewExpiredContext) Err() error {
	if c.Context.Err() != nil {
		return context.DeadlineExceeded
	}
	return nil
}

type overviewCloseReceipt struct {
	io.Reader
	close func()
}

func (b overviewCloseReceipt) Close() error { b.close(); return nil }

type overviewRoundTripper func(*http.Request) (*http.Response, error)

func (f overviewRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestOverviewFatalStateErrorCannotBecomeIsolatedDeadline(t *testing.T) {
	sender, h, _ := overviewFixture(t, "tls", 1, 1)
	parent, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx := overviewExpiredContext{parent}
	sender.processes.client = &http.Client{Transport: overviewRoundTripper(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		m, e := overviewwire.DecodeMessage("begin", raw)
		if e != nil {
			t.Fatal("request fixture")
		}
		receipt := overviewTestReceipt(m, raw, map[string]any{"startedAt": h.clock.now(), "expiresAt": h.clock.now().Add(15 * time.Minute)})
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: overviewCloseReceipt{Reader: bytes.NewReader(receipt), close: func() { sender.processes.state.Close(); cancel() }}, Request: r}, nil
	})}
	_, err := sender.Burst(ctx)
	if !errors.Is(err, ErrState) || overviewSchedulingError(context.Background(), err) == nil {
		t.Fatal("fatal trusted state became an isolated deadline", err)
	}
}
func TestOverviewExpiredContextDoesNotMaskStorageFailure(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, err := range []error{overviewstate.ErrCorrupt, overviewstate.ErrIO, overviewstate.ErrUncertain, overviewstate.ErrClosed} {
		if e := overviewStateError(ctx, err); !errors.Is(e, ErrState) {
			t.Fatal("storage failure became deadline", e)
		}
	}
	if e := overviewStateError(ctx, overviewstate.ErrCanceled); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("clean cancellation lost", e)
	}
}
