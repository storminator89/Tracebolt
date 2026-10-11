package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistoryworker"
	"localrmm/internal/windowsservice"
)

func historyWorkerFixture(t *testing.T) windowshistoryworker.Request {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true, HistoryAcknowledged: true}
	local := windowshistoryrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64)}
	r, e := windowshistoryrequest.NewSearch(local.DeviceID, local.CertificateHash, 1, c.GrantID, windowseventhistory.Search{Channel: "Application", Start: now.Add(-24 * time.Hour), End: now.Add(-time.Minute)}, now.Add(-2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	r, e = windowshistoryrequest.Claim(r, r.Description.Identity, c, local, now.Add(-time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return windowshistoryworker.Request{Description: r.Description, PolicyDigest: r.PolicyDigest, ClaimedAt: *r.ClaimedAt, Local: local, Consent: c}
}
func TestEventHistoryWorkerRechecksCreatorAtEveryBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "denied", "parent", "creation", "path", "hash", "sid", "consumption"} {
		for _, boundary := range []int{1, 2, 3} {
			t.Run(mode+string(rune('0'+boundary)), func(t *testing.T) {
				req := historyWorkerFixture(t)
				raw, _ := json.Marshal(req)
				checks, consumed, reads := 0, 0, 0
				identity := windowsservice.ObservationWorkerIdentity{Layout: windowsservice.Layout{EnrollmentRoot: "fixed-fixture"}, ParentProcessID: 10, ParentCreated: 100, ServiceSID: "fixture", ExecutableSHA256: strings.Repeat("1", 64)}
				var out bytes.Buffer
				e := serveEventHistoryWorker(context.Background(), bytes.NewReader(raw), &out, func(context.Context) (windowsservice.ObservationWorkerIdentity, error) {
					checks++
					v := identity
					if checks == boundary {
						switch mode {
						case "denied":
							return v, lanclient.ErrState
						case "parent":
							v.ParentProcessID++
						case "creation":
							v.ParentCreated++
						case "path":
							v.Layout.EnrollmentRoot = "another"
						case "hash":
							v.ExecutableSHA256 = strings.Repeat("2", 64)
						case "sid":
							v.ServiceSID = "another"
						}
					}
					return v, nil
				}, func(path string, r windowshistoryworker.Request) (windowshistoryworker.Request, error) {
					if path != filepath.Join(identity.Layout.EnrollmentRoot, "agent.json") {
						return windowshistoryworker.Request{}, lanclient.ErrState
					}
					return r, nil
				}, func(_ context.Context, path string, r windowshistoryworker.Request) error {
					consumed++
					if path != filepath.Join(identity.Layout.EnrollmentRoot, "agent.json") {
						t.Fatal("consumption used IPC path")
					}
					if mode == "consumption" {
						return errors.New("ambiguous durable write")
					}
					return nil
				}, func(_ context.Context, r windowshistoryworker.Request) (windowseventhistory.Report, error) {
					reads++
					if consumed != 1 {
						t.Fatal("read before consume")
					}
					return windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: windowseventhistory.QualityObserved, CollectedAt: time.Now().UTC(), Complete: true, Search: windowseventhistory.CloneSearch(r.Description.Query.Search), Events: []windowseventhistory.Result{}}, nil
				})
				if mode == "valid" {
					if e != nil || out.Len() == 0 || checks != 3 || consumed != 1 || reads != 1 {
						t.Fatal("valid worker failed", e, checks, consumed, reads)
					}
					return
				}
				if e == nil || out.Len() != 0 {
					t.Fatal("authority failure released content", mode, boundary)
				}
				if mode == "consumption" && reads != 0 || mode == "denied" && boundary < 3 && reads != 0 || boundary == 2 && reads != 0 {
					t.Fatal("failed boundary read source")
				}
			})
		}
	}
}
