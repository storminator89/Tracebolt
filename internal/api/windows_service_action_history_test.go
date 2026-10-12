package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seedWindowsActionHistory(t *testing.T, f *windowsActionAPIFixture, count int) {
	t.Helper()
	f.at = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	for n := 0; n < count; n++ {
		f.record.ClockFloor = f.at
		f.record.Capabilities.CapturedAt = f.at.Unix()
		op := []string{"start", "stop", "restart"}[n%3]
		if err := f.record.MakePreview(fmt.Sprintf("action_%032x", n+1), namedActorID, "FixtureService", op, f.at); err != nil {
			t.Fatal(err)
		}
		p := f.record.Preview
		if err := f.record.Approve(p.ID, p.Digest, namedActorID, f.at, func(p windowsaction.Permit) ([]byte, error) {
			m, e := windowsaction.SigningMessage(p)
			if e != nil {
				return nil, e
			}
			return windowsaction.Encode(p, ed25519.Sign(f.key, m))
		}); err != nil {
			t.Fatal(err)
		}
		j := f.record.Jobs[n]
		// Alternate observed completion with an unclaimed original deadline.
		if n%2 == 0 {
			if _, err := f.record.Claim(j.Identity(), f.at); err != nil {
				t.Fatal(err)
			}
			result := windowsaction.Result{Version: windowsaction.ResultVersion, Identity: j.Identity(), Operation: op, Target: "FixtureService", Deadline: j.Deadline().Unix(), Phase: "complete", Outcome: "running-observed", LastObservedState: 4, Observations: 4}
			if op != "start" {
				result.StopAttempted = true
				result.StopRequested = true
				result.StoppedObserved = true
			}
			if op != "stop" {
				result.StartAttempted = true
				result.StartRequested = true
				result.RunningObserved = true
			} else {
				result.Outcome = "stopped-observed"
				result.LastObservedState = 1
			}
			if err := f.record.Accept(result); err != nil {
				t.Fatal(err)
			}
		}
		f.at = f.at.Add(61 * time.Second)
	}
	f.record.ClockFloor = f.at
	if err := windowsactionjob.Validate(f.record); err != nil {
		t.Fatal(err)
	}
}
func TestWindowsServiceActionHistoryBoundedReadOnlyAndDetails(t *testing.T) {
	o, f, _ := windowsActionOperator(t)
	seedWindowsActionHistory(t, f, 64)
	before, _ := json.Marshal(f.record)
	base := "/api/devices/" + namedDeviceID + "/windows-service-actions/history"
	r, v := o.call(t, "GET", base, nil, "", nil)
	jobs, ok := v["jobs"].([]any)
	if r.StatusCode != 200 || !ok || len(jobs) != 64 || v["limit"] != float64(64) {
		t.Fatal(r.StatusCode, v)
	}
	if jobs[0].(map[string]any)["identity"].(map[string]any)["sequence"] != "64" || jobs[63].(map[string]any)["identity"].(map[string]any)["sequence"] != "1" {
		t.Fatal("history order")
	}
	raw, _ := json.Marshal(v)
	if len(raw) > 65536 {
		t.Fatal("history response exceeded bound")
	}
	for _, bad := range []string{`"envelope"`, `"signature"`, `"publicKey"`, `"preview"`, `"results"`} {
		if bytes.Contains(raw, []byte(bad)) {
			t.Fatal("unsafe history projection", bad)
		}
	}
	for _, n := range []int{0, 63} {
		saved := f.record.Jobs[n]
		r, v = o.call(t, "GET", base+"/"+saved.Preview.ID, nil, "", nil)
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode, v)
		}
		b, _ := json.Marshal(v)
		var detail windowsServiceActionHistoryDetail
		if json.Unmarshal(b, &detail) != nil {
			t.Fatal("detail")
		}
		if detail.Job.Identity != saved.Identity() || !detail.Job.ApprovedAt.Equal(saved.ApprovedAt) || detail.Job.StartDeadline != saved.Deadline() || detail.Binding != saved.Preview.Binding || detail.Job.State != saved.State(f.at) {
			t.Fatal("original receipt changed")
		}
		if n == 0 && (detail.ClaimedAt == nil || !detail.ClaimedAt.Equal(*saved.ClaimedAt) || detail.Job.Result == nil) {
			t.Fatal("claim or result lost")
		}
		if n == 63 && (detail.ClaimedAt != nil || detail.Job.Result != nil || detail.Job.State != "expired") {
			t.Fatal("expired history fabricated execution")
		}
	}
	after, _ := json.Marshal(f.record)
	if !bytes.Equal(before, after) || f.approvals != 0 || f.next != 0 {
		t.Fatal("history changed execution state")
	}
	r, _ = o.call(t, "GET", base+"/action_"+strings.Repeat("f", 32), nil, "", nil)
	if r.StatusCode != 404 {
		t.Fatal("missing job", r.StatusCode)
	}
	r, _ = o.call(t, "POST", base, nil, "", nil)
	if r.StatusCode != 405 {
		t.Fatal("history allowed mutation", r.StatusCode)
	}
}

type windowsActionHistoryViewFixture struct {
	*windowsActionAPIFixture
	view func(context.Context, string) (windowsactionjob.Record, time.Time, error)
}

func (f windowsActionHistoryViewFixture) ViewAt(ctx context.Context, device string) (windowsactionjob.Record, time.Time, error) {
	return f.view(ctx, device)
}
func TestWindowsServiceActionHistoryAccessAndFinalSession(t *testing.T) {
	for _, detail := range []bool{false, true} {
		t.Run(fmt.Sprint(detail), func(t *testing.T) {
			o, f, _ := windowsActionOperator(t)
			seedWindowsActionHistory(t, f, 1)
			path := "/api/devices/" + namedDeviceID + "/windows-service-actions/history"
			if detail {
				path += "/" + f.record.Jobs[0].Preview.ID
			}
			h := o.server.Config.Handler.(*operatorHandler)
			for _, err := range []error{enrollmentstate.ErrExpired, enrollmentstate.ErrProof, enrollmentstate.ErrNotFound, windowsaction.ErrUnavailable} {
				h.windowsActions = windowsActionHistoryViewFixture{f, func(context.Context, string) (windowsactionjob.Record, time.Time, error) { return f.record, f.at, err }}
				r, v := o.call(t, "GET", path, nil, "", nil)
				if r.StatusCode == 200 || v["jobs"] != nil || v["job"] != nil || v["binding"] != nil {
					t.Fatal("history escaped failed authority", r.StatusCode, v)
				}
			}
			u, _ := url.Parse(o.server.URL)
			var token string
			for _, cookie := range o.client.Jar.Cookies(u) {
				if cookie.Name == h.cookieName {
					token = cookie.Value
				}
			}
			if token == "" {
				t.Fatal("missing synthetic session")
			}
			h.windowsActions = windowsActionHistoryViewFixture{f, func(_ context.Context, _ string) (windowsactionjob.Record, time.Time, error) {
				h.auth.Logout(token)
				return f.record, f.at, nil
			}}
			r, v := o.call(t, "GET", path, nil, "", nil)
			if r.StatusCode != 401 || v["job"] != nil || v["jobs"] != nil {
				t.Fatal("after-wait session loss disclosed history", r.StatusCode, v)
			}
		})
	}
	o, _ := namedOperatorFixture(t)
	_, _ = o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	r, _ := o.call(t, "GET", "/api/devices/"+namedDeviceID+"/windows-service-actions/history", nil, "", nil)
	if r.StatusCode != 403 {
		t.Fatal("Linux grant read Windows history", r.StatusCode)
	}
}
func TestWindowsServiceActionHistoryAPIGoldenInterop(t *testing.T) {
	o, f, _ := windowsActionOperator(t)
	seedWindowsActionHistory(t, f, 3)
	base := "/api/devices/" + namedDeviceID + "/windows-service-actions/history"
	_, list := o.call(t, http.MethodGet, base, nil, "", nil)
	details := []any{}
	for n := len(f.record.Jobs) - 1; n >= 0; n-- {
		r, v := o.call(t, http.MethodGet, base+"/"+f.record.Jobs[n].Preview.ID, nil, "", nil)
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode)
		}
		details = append(details, v)
	}
	all := map[string]any{"actorId": namedActorID, "deviceId": namedDeviceID, "history": list, "details": details}
	raw, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-service-action-history.json")
	if os.Getenv("TRACEBOLT_UPDATE_WINDOWS_ACTION_HISTORY_FIXTURE") == "1" {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(want, raw) {
		t.Fatal("history interop fixture changed; explicitly regenerate and verify UI", err)
	}
}
