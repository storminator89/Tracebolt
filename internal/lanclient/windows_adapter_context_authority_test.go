//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsstate"
	"net/http"
	"testing"
	"time"
)

func adapterCurrentConsentFixture(t *testing.T, m Material, reload func(string) (Material, error)) func() (windowsadapters.Consent, bool) {
	t.Helper()
	raw, err := windowsadapters.EncodeConsent(adapterConsentFixture(m), m.binding)
	if err != nil {
		t.Fatal(err)
	}
	return func() (windowsadapters.Consent, bool) {
		return readWindowsAdapterContextConsentWithDependencies(m, windowsContextConsentDependencies{reload, func(string, windowsstate.Options) (windowsContextConsentStore, error) {
			return &adapterContextConsentMemory{raw: raw}, nil
		}})
	}
}

func TestWindowsAdapterContextCurrentAuthorityBeforeReceipt(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed", "ready-replaced", "load-denied"} {
		t.Run(kind, func(t *testing.T) {
			m, reload, change := windowsActivatedMaterialFixture(t)
			read := adapterCurrentConsentFixture(t, m, reload)
			if c, ok := read(); !ok || c != adapterConsentFixture(m) {
				t.Fatal("current authority rejected")
			}
			change(kind)
			_, ok := readWindowsAdapterContextConsentWithDependencies(m, windowsContextConsentDependencies{reload, func(string, windowsstate.Options) (windowsContextConsentStore, error) {
				t.Fatal("receipt opened before rejecting stale authority")
				return nil, nil
			}})
			if ok {
				t.Fatal("stale authority accepted")
			}
		})
	}
}

func TestWindowsAdapterContextCurrentIdentitySuppressesPendingRetry(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
		for _, phase := range []string{"before-retry", "retry-before-send"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, reload, change := windowsActivatedMaterialFixture(t)
				state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				read := adapterCurrentConsentFixture(t, m, reload)
				var bodies [][]byte
				var sent frame
				send := func(req *http.Request) (*http.Response, error) {
					raw, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatal(err)
					}
					bodies = append(bodies, bytes.Clone(raw))
					sent = frame{}
					if json.Unmarshal(raw, &sent) != nil {
						t.Fatal("frame")
					}
					return nil, errors.New("fixture offline")
				}
				_, err = runAdaptersOnlyWithAuthority(context.Background(), m, state, send, read, adapterSourceFixture, func() bool { return currentWindowsContextMaterial(m, reload) })
				if !errors.Is(err, ErrTransport) || sent.WindowsAdapterContext == nil {
					t.Fatal("missing pending", err)
				}
				first, err := state.Pending()
				if err != nil || first == nil {
					t.Fatal("pending fixture", err)
				}
				if phase == "before-retry" {
					change(kind)
				}
				reads := 0
				report, err := runAdaptersOnlyWithAuthority(context.Background(), m, state, send, func() (windowsadapters.Consent, bool) {
					reads++
					if phase == "retry-before-send" && reads == 2 {
						change(kind)
					}
					return read()
				}, func(context.Context, string, string, time.Time) (windowsadapters.Snapshot, error) {
					t.Fatal("stale or pending identity recollected adapters")
					return windowsadapters.Snapshot{}, nil
				}, func() bool { return currentWindowsContextMaterial(m, reload) })
				if phase == "before-retry" {
					retained, pendingErr := state.Pending()
					if !errors.Is(err, ErrState) || report.DiscardedUnconsented || report.RetriedPending || len(bodies) != 1 || pendingErr != nil || retained == nil || retained.Digest != first.Digest || !bytes.Equal(retained.Body(), first.Body()) {
						t.Fatal("stale private adapter context retried", err, report)
					}
				} else {
					retained, pendingErr := state.Pending()
					if !errors.Is(err, ErrState) || report.DiscardedUnconsented || !report.RetriedPending || reads != 2 || len(bodies) != 1 || pendingErr != nil || retained == nil || retained.Digest != first.Digest || !bytes.Equal(retained.Body(), first.Body()) {
						t.Fatal("retry pre-send authority or exact pending retention failed", err, report)
					}
				}
			})
		}
	}
}

func TestWindowsAdapterContextCurrentIdentityAfterCaptureAndBeforeSend(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
		for _, phase := range []string{"after-capture", "before-send"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, reload, change := windowsActivatedMaterialFixture(t)
				state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				read := adapterCurrentConsentFixture(t, m, reload)
				reads, captures := 0, 0
				sent := false
				_, err = runAdaptersOnlyWithAuthority(context.Background(), m, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowsadapters.Consent, bool) {
					reads++
					if phase == "before-send" && reads == 4 {
						change(kind)
					}
					return read()
				}, func(ctx context.Context, generation, grant string, at time.Time) (windowsadapters.Snapshot, error) {
					captures++
					s, err := adapterSourceFixture(ctx, generation, grant, at)
					if phase == "after-capture" {
						change(kind)
					}
					return s, err
				}, func() bool { return currentWindowsContextMaterial(m, reload) })
				pending, pendingErr := state.Pending()
				if !errors.Is(err, ErrState) || sent || captures != 1 || pendingErr != nil || (pending != nil) != (phase == "before-send") || reads != map[string]int{"after-capture": 3, "before-send": 4}[phase] {
					t.Fatal("stale identity staged or sent", err, reads, captures)
				}
			})
		}
	}
}
