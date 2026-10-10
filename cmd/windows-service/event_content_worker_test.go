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
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventworker"
	"localrmm/internal/windowsservice"
)

func eventWorkerFixture(t *testing.T) windowseventworker.Request {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	c := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	local := windowseventrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64)}
	h := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("e", 32), GenerationID: "sample_" + strings.Repeat("f", 32), CollectedAt: now.Add(-time.Minute), Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 1, Level: 2, Provider: "Synthetic", Timestamp: now.Add(-time.Minute)}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	r, e := windowseventrequest.New(local.DeviceID, local.CertificateHash, 1, c.GrantID, h, []windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}}, now.Add(-2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	r, e = windowseventrequest.Claim(r, r.Description.Identity, c, local, now.Add(-time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return windowseventworker.Request{Description: r.Description, PolicyDigest: r.PolicyDigest, ClaimedAt: *r.ClaimedAt, Local: local, Consent: c}
}
func TestEventContentWorkerRechecksCreatorAtEveryBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "denied", "parent", "creation", "path", "hash", "sid", "consumption"} {
		for _, boundary := range []int{1, 2, 3} {
			t.Run(mode+string(rune('0'+boundary)), func(t *testing.T) {
				req := eventWorkerFixture(t)
				raw, _ := json.Marshal(req)
				checks, consumed, reads := 0, 0, 0
				identity := windowsservice.ObservationWorkerIdentity{Layout: windowsservice.Layout{EnrollmentRoot: "fixed-fixture"}, ParentProcessID: 10, ParentCreated: 100, ServiceSID: "fixture", ExecutableSHA256: strings.Repeat("1", 64)}
				var out bytes.Buffer
				e := serveEventContentWorker(context.Background(), bytes.NewReader(raw), &out, func(context.Context) (windowsservice.ObservationWorkerIdentity, error) {
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
				}, func(path string, r windowseventworker.Request) (windowseventworker.Request, error) {
					if path != filepath.Join(identity.Layout.EnrollmentRoot, "agent.json") {
						return windowseventworker.Request{}, lanclient.ErrState
					}
					return r, nil
				}, func(_ context.Context, path string, r windowseventworker.Request) error {
					consumed++
					if path != filepath.Join(identity.Layout.EnrollmentRoot, "agent.json") {
						t.Fatal("consumption used IPC path")
					}
					if mode == "consumption" {
						return errors.New("ambiguous durable write")
					}
					return nil
				}, func(_ context.Context, r windowseventworker.Request) (windowseventcontent.Report, error) {
					reads++
					if consumed != 1 {
						t.Fatal("read before consume")
					}
					return windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: windowseventcontent.QualityObserved, CollectedAt: time.Now().UTC(), Complete: true, Events: []windowseventcontent.Result{{Event: r.Description.Query.Events[0], Message: "Synthetic", Quality: windowseventcontent.QualityObserved, Complete: true}}}, nil
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
