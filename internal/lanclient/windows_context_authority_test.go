//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
	"net/http"
	"testing"
)

type windowsContextAuthorityCase struct {
	name      string
	consent   any
	directory string
	options   windowsstate.Options
	read      func(windowsContextConsentDependencies) bool
}

func windowsContextAuthorityCases(m Material) []windowsContextAuthorityCase {
	return []windowsContextAuthorityCase{
		{"events", eventConsentFixture(m), windowsEventConsentDirectory(m), windowsEventOptions("", false), func(d windowsContextConsentDependencies) bool {
			c, ok := readWindowsEventConsentWithDependencies(m, d)
			return ok && c == eventConsentFixture(m)
		}},
		{"volumes", volumeConsentFixture(m), windowsVolumeConsentDirectory(m), windowsVolumeOptions("", false), func(d windowsContextConsentDependencies) bool {
			c, ok := readWindowsVolumeConsentWithDependencies(m, d)
			return ok && c == volumeConsentFixture(m)
		}},
		{"process", processConsentFixture(m), windowsProcessMetricsConsentDirectory(m), windowsProcessMetricsOptions("", false), func(d windowsContextConsentDependencies) bool {
			c, ok := readWindowsProcessMetricsConsentWithDependencies(m, d)
			return ok && c == processConsentFixture(m)
		}},
		{"network", networkConsentFixture(m), windowsNetworkConsentDirectory(m), windowsNetworkOptions("", false), func(d windowsContextConsentDependencies) bool {
			c, ok := readWindowsNetworkConsentWithDependencies(m, d)
			return ok && c == networkConsentFixture(m)
		}},
		{"startup", serviceStartupConsentFixture(m), windowsServiceStartupConsentDirectory(m), windowsServiceStartupOptions("", false), func(d windowsContextConsentDependencies) bool {
			c, ok := readWindowsServiceStartupConsentWithDependencies(m, d)
			return ok && c == serviceStartupConsentFixture(m)
		}},
	}
}

func contextAuthorityDependencies(t *testing.T, c windowsContextAuthorityCase, reload func(string) (Material, error)) windowsContextConsentDependencies {
	t.Helper()
	raw, err := json.Marshal(c.consent)
	if err != nil {
		t.Fatal(err)
	}
	return windowsContextConsentDependencies{reload, func(path string, options windowsstate.Options) (windowsContextConsentStore, error) {
		if path != c.directory || options.RuntimeSID != "" || options.Create || options.LockName != c.options.LockName || options.TempName != c.options.TempName || options.MaxBytes != c.options.MaxBytes || len(options.Names) != 1 || options.Names[0] != "consent.json" {
			t.Fatal("receipt identity or protected scope options changed")
		}
		return &adapterContextConsentMemory{raw: raw}, nil
	}}
}

func runWindowsContextAuthorityScope(m Material, state *lanclientstate.State, send func(*http.Request) (*http.Response, error), name string, d windowsContextConsentDependencies) (Report, error) {
	var events func() (windowseventhealth.Consent, bool)
	var volumes func() (windowsvolumes.Consent, bool)
	var process func() (windowsprocessmetrics.Consent, bool)
	var network func() (windowsnetwork.Consent, bool)
	var startup func() (windowsmanaged.ServiceStartupConsent, bool)
	switch name {
	case "events":
		events = func() (windowseventhealth.Consent, bool) { return readWindowsEventConsentWithDependencies(m, d) }
	case "volumes":
		volumes = func() (windowsvolumes.Consent, bool) { return readWindowsVolumeConsentWithDependencies(m, d) }
	case "process":
		process = func() (windowsprocessmetrics.Consent, bool) {
			return readWindowsProcessMetricsConsentWithDependencies(m, d)
		}
	case "network":
		network = func() (windowsnetwork.Consent, bool) { return readWindowsNetworkConsentWithDependencies(m, d) }
	case "startup":
		startup = func() (windowsmanaged.ServiceStartupConsent, bool) {
			return readWindowsServiceStartupConsentWithDependencies(m, d)
		}
	}
	return runUsingStateWithPatchContextAuthorityDependencies(context.Background(), m, state, nil, nil, nil, startupWindowsSource, send, events, eventSourceFixture, volumes, volumeSourceFixture, process, processSourceFixture, network, networkSourceFixture, startup, serviceStartupSourceFixture, nil, nil, nil, nil, nil, nil, func() bool { return currentWindowsContextMaterial(m, d.reload) })
}

func TestWindowsContextReadersRequireCurrentAuthorityBeforeReceipt(t *testing.T) {
	for index := range windowsContextAuthorityCases(Material{}) {
		for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed", "ready-replaced", "load-denied"} {
			m, reload, change := windowsActivatedMaterialFixture(t)
			c := windowsContextAuthorityCases(m)[index]
			t.Run(c.name+"/"+kind, func(t *testing.T) {
				d := contextAuthorityDependencies(t, c, reload)
				if !c.read(d) {
					t.Fatal("current authority rejected")
				}
				change(kind)
				d.open = func(string, windowsstate.Options) (windowsContextConsentStore, error) {
					t.Fatal("receipt opened under stale authority")
					return nil, nil
				}
				if c.read(d) {
					t.Fatal("stale authority accepted")
				}
			})
		}
	}
}

func TestWindowsContextReadersSuppressPendingRetryAfterAuthorityChange(t *testing.T) {
	for index := range windowsContextAuthorityCases(Material{}) {
		for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
			m, reload, change := windowsActivatedMaterialFixture(t)
			c := windowsContextAuthorityCases(m)[index]
			t.Run(c.name+"/"+kind, func(t *testing.T) {
				state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				d := contextAuthorityDependencies(t, c, reload)
				var sent frame
				send := func(req *http.Request) (*http.Response, error) {
					sent = frame{}
					if json.NewDecoder(req.Body).Decode(&sent) != nil {
						t.Fatal("frame")
					}
					return nil, errors.New("fixture offline")
				}
				_, err = runWindowsContextAuthorityScope(m, state, send, c.name, d)
				if !errors.Is(err, ErrTransport) || sent.SchemaVersion == FrameWindowsInventoryVersion {
					t.Fatal("missing consented pending", err)
				}
				first, pendingErr := state.Pending()
				if pendingErr != nil || first == nil {
					t.Fatal("pending fixture", pendingErr)
				}
				change(kind)
				d.open = func(string, windowsstate.Options) (windowsContextConsentStore, error) {
					t.Fatal("stale receipt read during pending retry")
					return nil, nil
				}
				report, err := runWindowsContextAuthorityScope(m, state, send, c.name, d)
				retained, pendingErr := state.Pending()
				if !errors.Is(err, ErrState) || report.DiscardedUnconsented || report.RetriedPending || pendingErr != nil || retained == nil || retained.Digest != first.Digest || !bytes.Equal(retained.Body(), first.Body()) {
					t.Fatal("stale private scope retried", err, report)
				}
			})
		}
	}
}

func TestWindowsContextReadersRecheckAuthorityAfterCapture(t *testing.T) {
	for index := range windowsContextAuthorityCases(Material{}) {
		m, reload, change := windowsActivatedMaterialFixture(t)
		c := windowsContextAuthorityCases(m)[index]
		t.Run(c.name, func(t *testing.T) {
			state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			reads := 0
			postCapture := 2
			if c.name == "startup" {
				postCapture = 3 // Startup also checks immediately before its source.
			}
			d := contextAuthorityDependencies(t, c, reload)
			open := d.open
			d.open = func(path string, options windowsstate.Options) (windowsContextConsentStore, error) {
				reads++
				if reads == postCapture {
					change("ready-removed")
				}
				return open(path, options)
			}
			_, err = runWindowsContextAuthorityScope(m, state, func(*http.Request) (*http.Response, error) {
				t.Fatal("stale private scope sent")
				return nil, nil
			}, c.name, d)
			pending, pendingErr := state.Pending()
			if !errors.Is(err, ErrState) || reads != postCapture || pendingErr != nil || pending != nil {
				t.Fatal("stale private capture staged", err, reads)
			}
		})
	}
}
