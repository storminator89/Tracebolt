//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/model"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowspatchcontext"
	"net/http"
	"testing"
)

func runAdaptersOnlyWithAuthority(ctx context.Context, m Material, state *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowsadapters.Consent, bool), collect adapterContextCollector, authority func() bool) (Report, error) {
	return runUsingStateWithPatchContextAuthorityDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect, nil, nil, authority)
}
func runPatchOnlyWithAuthority(ctx context.Context, m Material, state *lanclientstate.State, send func(*http.Request) (*http.Response, error), read func() (windowspatchcontext.Consent, bool), collect patchContextCollector, authority func() bool) (Report, error) {
	return runUsingStateWithPatchContextAuthorityDependencies(ctx, m, state, nil, nil, nil, startupWindowsSource, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, read, collect, authority)
}
func runWindowsBaseWithAuthority(m Material, state *lanclientstate.State, collect windowsCollector, send func(*http.Request) (*http.Response, error), authority func() bool) (Report, error) {
	return runUsingStateWithPatchContextAuthorityDependencies(context.Background(), m, state, nil, nil, syntheticPackageBasic, collect, send, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, authority)
}

func TestWindowsInventoryCurrentAuthorityBoundaries(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
		for _, phase := range []string{"attempt-start", "before-capture", "after-capture", "before-send"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, reload, change := windowsActivatedMaterialFixture(t)
				state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				calls, captures := 0, 0
				stop := map[string]int{"attempt-start": 1, "before-capture": 3, "after-capture": 4, "before-send": 5}[phase]
				_, err = runWindowsBaseWithAuthority(m, state, func(ctx context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
					captures++
					return startupWindowsSource(ctx, generation)
				}, func(*http.Request) (*http.Response, error) {
					t.Fatal("base inventory sent under stale authority")
					return nil, nil
				}, func() bool {
					calls++
					if calls == stop {
						change(kind)
					}
					return currentWindowsContextMaterial(m, reload)
				})
				pending, pendingErr := state.Pending()
				wantCapture := phase == "after-capture" || phase == "before-send"
				if !errors.Is(err, ErrState) || calls != stop || (captures == 1) != wantCapture || pendingErr != nil || (pending != nil) != (phase == "before-send") {
					t.Fatal("base identity boundary failed", err, calls, captures)
				}
			})
		}
	}
}

func TestWindowsInventoryCurrentAuthorityPreservesPendingBeforeDiscard(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
		for _, phase := range []string{"reader-loss", "before-discard"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, reload, change := windowsActivatedMaterialFixture(t)
				state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				current := func() bool { return currentWindowsContextMaterial(m, reload) }
				read := adapterCurrentConsentFixture(t, m, reload)
				sends := 0
				send := func(*http.Request) (*http.Response, error) { sends++; return nil, errors.New("fixture offline") }
				if _, err = runAdaptersOnlyWithAuthority(context.Background(), m, state, send, read, adapterSourceFixture, current); !errors.Is(err, ErrTransport) {
					t.Fatal("pending fixture", err)
				}
				first, pendingErr := state.Pending()
				if pendingErr != nil || first == nil {
					t.Fatal("pending fixture", pendingErr)
				}
				checks := 0
				report, err := runAdaptersOnlyWithAuthority(context.Background(), m, state, send, func() (windowsadapters.Consent, bool) {
					if phase == "reader-loss" {
						change(kind)
						return read()
					}
					c := adapterConsentFixture(m)
					c.Enabled = false
					return c, false
				}, nil, func() bool {
					checks++
					if phase == "before-discard" && checks == 3 {
						change(kind)
					}
					return current()
				})
				retained, pendingErr := state.Pending()
				if !errors.Is(err, ErrState) || report.DiscardedUnconsented || report.RetriedPending || sends != 1 || pendingErr != nil || retained == nil || retained.Digest != first.Digest || !bytes.Equal(retained.Body(), first.Body()) {
					t.Fatal("identity loss consumed exact pending bytes", err, report)
				}
			})
		}
	}
}

func TestWindowsInventoryCurrentAuthorityAllowsDisabledScopeAndExactBaseRetry(t *testing.T) {
	m, reload, _ := windowsActivatedMaterialFixture(t)
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	current := func() bool { return currentWindowsContextMaterial(m, reload) }
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
	if _, err = runAdaptersOnlyWithAuthority(context.Background(), m, state, send, adapterCurrentConsentFixture(t, m, reload), adapterSourceFixture, current); !errors.Is(err, ErrTransport) || sent.WindowsAdapterContext == nil {
		t.Fatal("pending fixture", err)
	}
	first := sent.Sequence
	report, err := runAdaptersOnlyWithAuthority(context.Background(), m, state, send, func() (windowsadapters.Consent, bool) {
		c := adapterConsentFixture(m)
		c.Enabled = false
		return c, false
	}, nil, current)
	if !errors.Is(err, ErrTransport) || !report.DiscardedUnconsented || report.RetriedPending || sent.SchemaVersion != FrameWindowsInventoryVersion || sent.WindowsAdapterContext != nil || sent.Sequence <= first || len(bodies) != 2 {
		t.Fatal("ordinary disabled scope blocked or leaked base", err, report)
	}
	report, err = runWindowsBaseWithAuthority(m, state, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
		t.Fatal("pending base recaptured")
		return windowsmanaged.Snapshot{}, model.Device{}, nil
	}, send, current)
	if !errors.Is(err, ErrTransport) || !report.RetriedPending || report.DiscardedUnconsented || len(bodies) != 3 || !bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("valid base retry changed", err, report)
	}
}

func TestWindowsInventoryRuntimeEntryRequiresCurrentAuthority(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test") // Valid cached material, no activated files.
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	_, err = runUsingStateWithCurrentDependencies(context.Background(), m, state, nil, nil, nil, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
		t.Fatal("runtime collected without current protected material")
		return windowsmanaged.Snapshot{}, model.Device{}, nil
	}, func(*http.Request) (*http.Response, error) {
		t.Fatal("runtime sent without current protected material")
		return nil, nil
	})
	if !errors.Is(err, ErrState) {
		t.Fatal("runtime authority bypassed", err)
	}
}

func TestWindowsInventoryAuthorityDoesNotGateLinuxBasic(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	m.config.SchemaVersion, m.config.CollectionProfile = ConfigVersion, ""
	leaf, err := x509.ParseCertificate(m.certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	binding := senderBinding(m.config, leaf)
	m.binding = hex.EncodeToString(binding[:])
	if !m.valid() {
		t.Fatal("basic fixture")
	}
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	sent := false
	_, err = runWindowsBaseWithAuthority(m, state, nil, func(*http.Request) (*http.Response, error) {
		sent = true
		return nil, errors.New("fixture offline")
	}, func() bool {
		t.Fatal("Windows authority applied to Linux basic")
		return false
	})
	if !errors.Is(err, ErrTransport) || !sent {
		t.Fatal("Linux behavior changed", err)
	}
}
