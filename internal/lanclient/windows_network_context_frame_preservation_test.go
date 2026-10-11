//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowsnetworkcontextwire"
	"localrmm/internal/windowssecuritycoverage"
)

// The fresh seventeen-scope approval includes independent full inventories, while
// optional cached WUA adds another old telemetry disclosure. Neither case may
// grow the old 16-entry / 16 KiB observation contract or discard its notices.
func TestWindowsNetworkContextFresh17HTTPPreservesAllEnabledV14Frame(t *testing.T) {
	for _, cachedWUA := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh17", true: "all-including-separate-cached-WUA"}[cachedWUA], func(t *testing.T) {
			m := windowsMaterialFixture(t, "http-test")
			c := readAdminV10Fixture()
			c.InsecureHTTPAcknowledged = true
			if c.Validate() != nil || len(c.Scopes) != 17 || c.Scopes[16] != windowsnetworkcontext.Scope {
				t.Fatal("fresh scope changed")
			}
			notices := strings.Join(WindowsReadAdminNoticesV10(true), "\n")
			if !strings.Contains(notices, windowsnetworkcontext.Privacy) || !strings.Contains(notices, windowsnetworkcontext.HTTPPrivacy) {
				t.Fatal("independent full-process disclosure missing")
			}
			ctx := withProcessMetricSelfPID(context.Background(), 7)
			f, _, e := collectWindowsFrame(ctx, m.config, 1, startupWindowsSource)
			if e != nil {
				t.Fatal(e)
			}
			stages := []func(frame) (frame, []byte, error){
				func(f frame) (frame, []byte, error) {
					return appendWindowsEvents(ctx, m, f, eventConsentFixture(m), eventSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsVolumes(ctx, m, f, volumeConsentFixture(m), volumeSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsProcessMetrics(ctx, m, f, processConsentFixture(m), processSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsNetwork(ctx, m, f, networkConsentFixture(m), networkSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsServiceStartup(ctx, m, f, serviceStartupConsentFixture(m), serviceStartupSourceFixture)
				},
			}
			if cachedWUA {
				stages = append(stages, func(f frame) (frame, []byte, error) {
					return appendWindowsUpdates(ctx, m, f, updatesConsentFixture(m), updatesSourceFixture)
				})
			}
			stages = append(stages,
				func(f frame) (frame, []byte, error) {
					return appendWindowsAdapterContext(ctx, m, f, adapterConsentFixture(m), adapterSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsPatchContext(ctx, m, f, patchConsentFixture(m), patchSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsSecurityPosture(ctx, m, f, securityConsentFixture(m), securitySourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsSessionContext(ctx, m, f, sessionConsentFixture(m), sessionSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsHardwareContext(ctx, m, f, hardwareConsentFixture(m), hardwareSourceFixture)
				},
				func(f frame) (frame, []byte, error) {
					return appendWindowsStorageContext(ctx, m, f, storageConsentFixture(m), storageSourceFixture)
				},
			)
			for i, stage := range stages {
				f, _, e = stage(f)
				if e != nil {
					t.Fatal("stage", i, e)
				}
			}
			priorNotices := append([]string(nil), f.Observation.Privacy...)
			f, _, e = appendWindowsSecurityCoverage(ctx, m, f, coverageConsentFixture(m), coverageSourceFixture)
			if e != nil {
				t.Fatal(e)
			}
			joined := strings.Join(f.Observation.Privacy, "\n")
			for _, notice := range priorNotices {
				if !strings.Contains(joined, notice) {
					t.Fatal("security v14 discarded earlier notice")
				}
			}
			if len(f.Observation.Privacy) != 16 || !strings.Contains(joined, windowssecuritycoverage.TelemetryPrivacy) {
				t.Fatal("old privacy bound/disclosure changed", len(f.Observation.Privacy))
			}
			// Keep every original notice, then fill only inert fixture text to exercise
			// the original observation boundary without changing its entry/string limits.
			obs, _ := json.Marshal(f.Observation)
			remain := MaxWindowsObservationBytes - 64 - len(obs)
			for i := 0; i < 3 && remain > 0; i++ {
				space := 4096 - len(f.Observation.Privacy[i])
				if space > remain {
					space = remain
				}
				f.Observation.Privacy[i] += strings.Repeat("x", space)
				remain -= space
			}
			obs, _ = json.Marshal(f.Observation)
			if remain != 0 || len(obs) != MaxWindowsObservationBytes-64 {
				t.Fatal("fixture did not reach observation boundary", len(obs), remain)
			}
			raw, e := json.Marshal(f)
			if e != nil || len(raw) > MaxFrameBytes {
				t.Fatal("frame budget", e)
			}
			if f.SchemaVersion != FrameWindowsSecurityCoverageVersion || f.WindowsProcessMetrics == nil || f.WindowsStorageContext == nil || f.WindowsSecurityCoverage == nil {
				t.Fatal("old scoped envelopes lost")
			}
			if _, e = decodeFrameForConfig(raw, 1, m.config); e != nil {
				t.Fatal("sender rejected full existing frame", e)
			}
			if _, e = lanstore.ValidateFrame(raw, time.Now().UTC()); e != nil {
				t.Fatal("manager rejected full existing frame", e)
			}
			state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			pending, e := state.Stage(1, raw)
			if e != nil {
				t.Fatal(e)
			}
			st := networkContextLocal(t, m)
			calls := 0
			now := time.Now().UTC()
			sender, e := newNetworkContextFixtureSender(m, st, func() time.Time { return now }, func(context.Context) (windowsnetworkcontext.Capture, error) {
				calls++
				return windowsnetworkcontext.Capture{StartedAt: now, FinishedAt: now, Complete: true, Rows: inventedNetworkContext(129)}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			sender.client = &http.Client{Transport: networkContextRoundTrip(func(req *http.Request) (*http.Response, error) {
				if !strings.HasPrefix(req.URL.Path, windowsnetworkcontextwire.PathPrefix) || req.URL.Path == WindowsTelemetryPath {
					t.Fatal("complete process rows entered old transport")
				}
				body, e := io.ReadAll(req.Body)
				if e != nil {
					t.Fatal(e)
				}
				message, e := windowsnetworkcontext.DecodeMessage(body)
				if e != nil {
					t.Fatal(e)
				}
				status := "accepted"
				if message.Operation == "chunk" && message.Index == message.Manifest.ChunkCount-1 {
					status = "complete"
				}
				receipt, _ := json.Marshal(windowsnetworkcontext.Receipt{SchemaVersion: windowsnetworkcontext.ReceiptVersion, Operation: message.Operation, DeviceID: message.DeviceID, GrantID: message.Consent.GrantID, GrantRevision: message.Consent.Revision, Sequence: message.Sequence, RequestSHA256: windowsnetworkcontext.Hash(body), Index: message.Index, Status: status, ReceivedAt: now})
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(receipt))}, nil
			})}
			report, e := sender.Burst(ctx)
			if e != nil || report.Status != "complete" || calls != 1 {
				t.Fatal(report, e, calls)
			}
			after, e := state.Pending()
			if e != nil || after == nil || after.Digest != pending.Digest || after.Sequence != pending.Sequence || !bytes.Equal(after.Body(), raw) {
				t.Fatal("full inventory changed old exact pending bytes", e)
			}
			got, _ := json.Marshal(f)
			if !bytes.Equal(got, raw) || bytes.Contains(raw, []byte(windowsnetworkcontext.Scope)) || bytes.Contains(raw, []byte(windowsnetworkcontext.Privacy)) {
				t.Fatal("full-process scope grew old frame/privacy")
			}
		})
	}
}
