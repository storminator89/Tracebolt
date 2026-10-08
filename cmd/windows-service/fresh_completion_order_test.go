package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsservice"
)

type freshCompletionFixture struct {
	receipt                  installReceipt
	calls                    []string
	fail, cancelAt, expireAt string
	cancel                   context.CancelFunc
	allowed                  bool
	running                  bool
	serviceCalls             int
}

func newFreshCompletionFixture(t *testing.T) *freshCompletionFixture {
	t.Helper()
	setup := &readSetupFixture{}
	if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), setup.hooks()); err != nil {
		t.Fatal("fixture setup")
	}
	return &freshCompletionFixture{receipt: setup.record, allowed: true}
}
func (f *freshCompletionFixture) visit(step string) error {
	f.calls = append(f.calls, step)
	if f.cancelAt == step {
		f.cancel()
	}
	if f.expireAt == step {
		f.allowed = false
	}
	if f.fail == step {
		return errors.New("PRIVATE_COMPLETION_SENTINEL")
	}
	return nil
}
func (f *freshCompletionFixture) steps(t *testing.T) freshCompletionSteps {
	return freshCompletionSteps{
		receipt: func() (installReceipt, error) {
			err := f.visit("receipt")
			var r installReceipt
			raw, _ := json.Marshal(f.receipt)
			_ = json.Unmarshal(raw, &r)
			if f.fail == "changed-receipt" {
				r.Service.InstallationID = "different"
			}
			return r, err
		},
		service: func(_ context.Context, r windowsservice.Receipt) error {
			if r != f.receipt.Service {
				t.Fatal("service binding changed")
			}
			f.serviceCalls++
			if f.fail == "restarted" && f.serviceCalls > 1 {
				return errors.New("PRIVATE_COMPLETION_SENTINEL")
			}
			if f.serviceCalls > 1 {
				return f.visit("service-final")
			}
			return f.visit("service")
		},
		identity: func(path string, c lanclient.WindowsCapabilityConsent) (string, error) {
			if f.running {
				t.Fatal("live sender store opened")
			}
			if path != filepath.Join(f.receipt.Service.Layout.EnrollmentRoot, "agent.json") || !reflect.DeepEqual(c, f.receipt.ReadSetup.Consent) {
				t.Fatal("identity scope changed")
			}
			err := f.visit("identity")
			if f.fail == "changed-identity" {
				return "different", nil
			}
			return f.receipt.ReadSetup.SenderBinding, err
		},
		grants: func(path string, c lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			if f.running {
				t.Fatal("live sender grants opened")
			}
			if path != filepath.Join(f.receipt.Service.Layout.EnrollmentRoot, "agent.json") || !reflect.DeepEqual(c, f.receipt.ReadSetup.Consent) {
				t.Fatal("grant scope changed")
			}
			err := f.visit("grants")
			grants := append([]lanclient.WindowsCapabilityGrantDigest(nil), f.receipt.ReadSetup.GrantDigests...)
			if f.fail == "changed-grant" {
				grants[0].SHA256 = "different"
			}
			if f.fail == "reordered-grants" {
				grants[0], grants[1] = grants[1], grants[0]
			}
			return grants, err
		},
	}
}
func TestFreshCompletionSeparatesLiveTokenAndStoppedStores(t *testing.T) {
	f := newFreshCompletionFixture(t)
	f.running = true
	live, err := freshLiveCompletion(context.Background(), func() bool { return f.allowed }, f.steps(t))
	if err != nil || !reflect.DeepEqual(live, f.receipt) || !reflect.DeepEqual(f.calls, []string{"receipt", "service"}) {
		t.Fatal("live completion opened an exclusive store or lost verification")
	}
	f.running = false
	f.calls = nil
	f.serviceCalls = 0
	if freshStoppedCompletion(context.Background(), func() bool { return f.allowed }, live, f.steps(t)) != nil {
		t.Fatal("stopped completion failed")
	}
	if !reflect.DeepEqual(f.calls, []string{"service", "receipt", "identity", "grants", "service-final"}) {
		t.Fatal("stopped readback order changed")
	}
}
func TestFreshCompletionLiveFailuresCannotReachStores(t *testing.T) {
	for _, failure := range []string{"receipt", "service"} {
		t.Run(failure, func(t *testing.T) {
			f := newFreshCompletionFixture(t)
			f.running = true
			f.fail = failure
			if _, err := freshLiveCompletion(context.Background(), func() bool { return f.allowed }, f.steps(t)); err == nil {
				t.Fatal("unverified live service accepted")
			}
			want := []string{"receipt"}
			if failure == "service" {
				want = append(want, "service")
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal("live failure continued")
			}
		})
	}
}
func TestFreshCompletionStoppedFailuresFailClosed(t *testing.T) {
	for _, failure := range []string{"service", "receipt", "changed-receipt", "identity", "changed-identity", "grants", "changed-grant", "reordered-grants", "restarted"} {
		t.Run(failure, func(t *testing.T) {
			f := newFreshCompletionFixture(t)
			f.fail = failure
			if freshStoppedCompletion(context.Background(), func() bool { return f.allowed }, f.receipt, f.steps(t)) == nil {
				t.Fatal("unproven stopped completion accepted")
			}
			if failure == "service" && !reflect.DeepEqual(f.calls, []string{"service"}) {
				t.Fatal("exclusive read preceded proven stop")
			}
		})
	}
}
func TestFreshCompletionCancellationAndExpiryAtEveryBoundary(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry"} {
		for _, step := range []string{"before", "receipt", "service", "identity", "grants", "service-final"} {
			t.Run(mode+"/"+step, func(t *testing.T) {
				f := newFreshCompletionFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.cancel = cancel
				if mode == "cancel" {
					f.cancelAt = step
					if step == "before" {
						cancel()
					}
				} else {
					f.expireAt = step
					if step == "before" {
						f.allowed = false
					}
				}
				if freshStoppedCompletion(ctx, func() bool { return f.allowed }, f.receipt, f.steps(t)) == nil {
					t.Fatal("cancelled or expired readback accepted")
				}
				if step == "before" && len(f.calls) != 0 {
					t.Fatal("invalid context invoked callbacks")
				}
				if step != "before" && f.calls[len(f.calls)-1] != step {
					t.Fatal("work continued beyond authorization boundary")
				}
			})
		}
	}
}
func TestFreshCompletionInvalidInputsNeverRead(t *testing.T) {
	f := newFreshCompletionFixture(t)
	s := f.steps(t)
	for _, mutate := range []func(*freshCompletionSteps){func(s *freshCompletionSteps) { s.receipt = nil }, func(s *freshCompletionSteps) { s.service = nil }, func(s *freshCompletionSteps) { s.identity = nil }, func(s *freshCompletionSteps) { s.grants = nil }} {
		broken := s
		mutate(&broken)
		if freshStoppedCompletion(context.Background(), func() bool { return true }, f.receipt, broken) == nil || len(f.calls) != 0 {
			t.Fatal("invalid stopped steps reached callbacks")
		}
	}
	if _, err := freshLiveCompletion(nil, func() bool { return true }, s); err == nil || len(f.calls) != 0 {
		t.Fatal("nil live context reached callbacks")
	}
	if freshStoppedCompletion(context.Background(), nil, f.receipt, s) == nil || len(f.calls) != 0 {
		t.Fatal("missing authority reached callbacks")
	}
	bad := f.receipt
	bad.Prepared = false
	if freshStoppedCompletion(context.Background(), func() bool { return true }, bad, s) == nil || len(f.calls) != 0 {
		t.Fatal("incomplete receipt reached callbacks")
	}
}

func TestFreshCompletionFinalAcceptanceAfterStopAndReadbackOnly(t *testing.T) {
	for _, mode := range []string{"passed", "not-ready", "unreaped", "console-open", "stop-failed", "not-stopped", "disabled", "not-automatic", "readback-failed"} {
		t.Run(mode, func(t *testing.T) {
			r := freshgate.NewReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			r.Status = "failed"
			r.OwnedChildReaped = mode != "unreaped"
			r.ConsoleClosed = mode != "console-open"
			calls := []string{}
			q := freshQuiescence{Stopped: mode != "not-stopped", Disabled: mode == "disabled", Automatic: mode != "disabled" && mode != "not-automatic" && mode != "not-stopped"}
			freshFinalizeCompletion(&r, mode != "not-ready", func() (freshQuiescence, error) {
				calls = append(calls, "stop")
				if mode == "stop-failed" {
					return freshQuiescence{}, errors.New("PRIVATE_STOP_SENTINEL")
				}
				return q, nil
			}, func() error {
				calls = append(calls, "readback")
				if mode == "readback-failed" {
					return errors.New("PRIVATE_READBACK_SENTINEL")
				}
				return nil
			})
			want := []string{"stop"}
			if mode == "unreaped" {
				want = []string{}
			}
			if mode == "passed" || mode == "readback-failed" {
				want = append(want, "readback")
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatal("cleanup readback ordering changed")
			}
			if mode == "passed" {
				if r.Status != "passed_fresh_native_subset" || !r.ReceiptAndGrantsVerified || !r.HiddenConsoleExercised || !r.FreshOrchestrationAcceptance || r.ControllerStage != "completed" {
					t.Fatal("verified completion not recorded")
				}
			} else if r.Status != "failed" || r.ReceiptAndGrantsVerified || r.HiddenConsoleExercised || r.FreshOrchestrationAcceptance {
				t.Fatal("failed verification became acceptance")
			}
			if mode != "unreaped" && mode != "stop-failed" && (r.OwnedServiceStopped != q.Stopped || r.ServiceDisabled != q.Disabled || r.AutomaticStartConfigurationRetained != q.Automatic) {
				t.Fatal("cleanup evidence was lost or relabeled")
			}
		})
	}
}

func TestFreshCompletionLiveCancellationAndExpiryAtEveryBoundary(t *testing.T) {
	for _, mode := range []string{"cancel", "expiry"} {
		for _, step := range []string{"before", "receipt", "service"} {
			t.Run(mode+"/"+step, func(t *testing.T) {
				f := newFreshCompletionFixture(t)
				f.running = true
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.cancel = cancel
				if mode == "cancel" {
					f.cancelAt = step
					if step == "before" {
						cancel()
					}
				} else {
					f.expireAt = step
					if step == "before" {
						f.allowed = false
					}
				}
				if _, err := freshLiveCompletion(ctx, func() bool { return f.allowed }, f.steps(t)); err == nil {
					t.Fatal("invalid live authority accepted")
				}
				if step == "before" && len(f.calls) != 0 {
					t.Fatal("invalid live authority invoked callback")
				}
				if step != "before" && f.calls[len(f.calls)-1] != step {
					t.Fatal("live work continued beyond authority")
				}
			})
		}
	}
}
