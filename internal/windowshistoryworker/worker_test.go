package windowshistoryworker

import (
	"bytes"
	"context"
	"errors"
	history "localrmm/internal/windowseventhistory"
	request "localrmm/internal/windowshistoryrequest"
	"strings"
	"testing"
	"time"
)

func workerFixture(t *testing.T) Request {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	c := request.Consent{SchemaVersion: request.ConsentVersion, Scope: request.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	l := request.LocalContext{SenderBinding: c.SenderBinding, Profile: c.Profile, DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64)}
	r, e := request.NewSearch(l.DeviceID, l.CertificateHash, 1, c.GrantID, history.Search{Channel: "System", Start: now.Add(-time.Hour), End: now}, now)
	if e != nil {
		t.Fatal(e)
	}
	r, e = request.Claim(r, r.Description.Identity, c, l, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	return Request{Description: r.Description, PolicyDigest: r.PolicyDigest, ClaimedAt: *r.ClaimedAt, Local: l, Consent: c}
}
func workerReport(req Request) history.Report {
	return history.Report{Source: history.Source, Warning: history.PrivacyWarning, Quality: history.QualityObserved, CollectedAt: time.Now().UTC(), Complete: true, Events: []history.Result{}, Search: history.CloneSearch(req.Description.Query.Search)}
}
func TestSearchWorkerConsumesBeforeReadAndRechecks(t *testing.T) {
	req := workerFixture(t)
	raw, e := encodeRequest(req)
	if e != nil {
		t.Fatal(e)
	}
	order := []string{}
	var out bytes.Buffer
	e = Serve(context.Background(), bytes.NewReader(raw), &out, func(_ context.Context, r Request) (Request, error) { order = append(order, "resolve"); return r, nil }, func(context.Context, Request) error { order = append(order, "consume"); return nil }, func(_ context.Context, r Request) (history.Report, error) {
		order = append(order, "read")
		return workerReport(r), nil
	})
	if e != nil || strings.Join(order, ",") != "resolve,consume,read,resolve" {
		t.Fatal("worker ordering changed")
	}
	report, e := decodeResponse(out.Bytes(), req, time.Now().UTC())
	if e != nil || !report.Complete || len(report.Events) != 0 || report.Search == nil {
		t.Fatal("empty exhausted search lost")
	}
}
func TestSearchWorkerFailureAndSecondAuthorityDenial(t *testing.T) {
	for _, phase := range []string{"consume", "second resolve"} {
		t.Run(phase, func(t *testing.T) {
			req := workerFixture(t)
			raw, _ := encodeRequest(req)
			reads, resolves := 0, 0
			var out bytes.Buffer
			e := Serve(context.Background(), bytes.NewReader(raw), &out, func(_ context.Context, r Request) (Request, error) {
				resolves++
				if phase == "second resolve" && resolves == 2 {
					return Request{}, request.ErrDisabled
				}
				return r, nil
			}, func(context.Context, Request) error {
				if phase == "consume" {
					return errors.New("private state error")
				}
				return nil
			}, func(_ context.Context, r Request) (history.Report, error) { reads++; return workerReport(r), nil })
			if e == nil || out.Len() != 0 || phase == "consume" && reads != 0 {
				t.Fatal("authority failure released data or read early")
			}
		})
	}
}
func TestSearchWorkerRetainsTruthfulUnavailableReport(t *testing.T) {
	req := workerFixture(t)
	raw, _ := encodeRequest(req)
	var out bytes.Buffer
	e := Serve(context.Background(), bytes.NewReader(raw), &out, func(_ context.Context, r Request) (Request, error) { return r, nil }, func(context.Context, Request) error { return nil }, func(_ context.Context, r Request) (history.Report, error) {
		report := workerReport(r)
		report.Complete = false
		report.Quality = history.QualityUnavailable
		report.Reason = history.ErrAccessDenied.Error()
		return report, history.ErrAccessDenied
	})
	if e != nil {
		t.Fatal(e)
	}
	report, e := decodeResponse(out.Bytes(), req, time.Now().UTC())
	if e != nil || report.Quality != history.QualityUnavailable || report.Complete {
		t.Fatal("unavailable became empty success")
	}
}
func TestWorkerClonesSearchPointersAndRejectsUnknownInput(t *testing.T) {
	req := workerFixture(t)
	clone := cloneRequest(req)
	clone.Description.Query.Search.Channel = "Application"
	if req.Description.Query.Search.Channel != "System" {
		t.Fatal("callback shares original query")
	}
	raw, _ := encodeRequest(req)
	bad := bytes.Replace(raw, []byte(`"description":`), []byte(`"executable":"shell","description":`), 1)
	if _, e := decodeRequest(bad); e == nil {
		t.Fatal("worker accepted arbitrary source selector")
	}
	if WorkerArgument != "--internal-windows-event-history-worker" || WorkerBudget != 10*time.Second {
		t.Fatal("worker domain or budget changed")
	}
}
