//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func completeMVPOverviewQueryFixture(t *testing.T) (completeMVPOverviewView, completeMVPOverviewPage, completeMVPOverviewQueryInput, []byte) {
	t.Helper()
	view, rows, _ := completeMVPOverviewFixture(t)
	complete := view.Processes.Complete
	page := completeMVPOverviewPage{SchemaVersion: "tracebolt.complete-overview-page.v1", DeviceID: view.DeviceID, Section: "processes", ServerNow: view.ServerNow, Binding: complete.Binding, Manifest: complete.Manifest, CollectedAt: complete.Manifest.CollectedAt, CompletedAt: complete.CompletedAt, RetainedUntil: complete.RetainedUntil, TotalRows: uint64(len(rows)), Items: rows, ScannedRows: len(rows), Exhausted: true, CursorExpiresAt: view.ServerNow.Add(time.Minute)}
	input := completeMVPOverviewQueryInput{Section: "processes", GenerationID: complete.Binding.GenerationID, Cursor: "opaque-fixture-cursor", Search: "", Limit: 100}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal("overview_query_fixture_encode")
	}
	return view, page, input, raw
}

func TestCompleteMVPOverviewQueryExactBusyThenPage(t *testing.T) {
	view, expected, input, pageRaw := completeMVPOverviewQueryFixture(t)
	requestRaw, _ := json.Marshal(input)
	calls, waits := 0, 0
	var deadline time.Time
	var firstHeader http.Header
	var busyBody *completeMVPOverviewQueryBody
	jar, _ := cookiejar.New(nil)
	origin := "http://fixture.invalid"
	uri, _ := url.Parse(origin)
	jar.SetCookies(uri, []*http.Cookie{{Name: "session", Value: "fixture-session", Path: "/"}})
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		current, ok := r.Context().Deadline()
		raw, err := io.ReadAll(r.Body)
		r.Body.Close()
		if !ok || err != nil || r.Method != http.MethodPost || r.URL.String() != origin+"/api/devices/"+view.DeviceID+"/inventory/overview/query" || !bytes.Equal(raw, requestRaw) || r.ContentLength != int64(len(requestRaw)) || r.GetBody != nil {
			t.Fatal("overview_query_request_or_deadline_changed")
		}
		if r.Header.Get("Origin") != origin || r.Header.Get("X-CSRF-Token") != "fixture-csrf" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cookie") != "session=fixture-session" {
			t.Fatal("overview_query_authority_changed")
		}
		if calls == 1 {
			deadline, firstHeader = current, r.Header.Clone()
			if remaining := time.Until(deadline); remaining <= 0 || remaining > 5*time.Second {
				t.Fatal("overview_query_original_bound_changed")
			}
			response := completeMVPOperatorResponse(429, completeMVPBusyJSON, "2")
			busyBody = &completeMVPOverviewQueryBody{Reader: response.Body}
			response.Body = busyBody
			response.Header.Add("Set-Cookie", "session=response-rotation; Path=/")
			return response, nil
		}
		if calls != 2 || current != deadline || !reflect.DeepEqual(firstHeader, r.Header) {
			t.Fatal("overview_query_retry_changed_bytes_headers_or_deadline")
		}
		return completeMVPOperatorResponse(200, string(pageRaw), ""), nil
	})}
	page, result := completeMVPOverviewQueryRead(context.Background(), client, origin, view.DeviceID, "fixture-csrf", input, func(ctx context.Context, delay time.Duration) error {
		waits++
		actual, _ := ctx.Deadline()
		if actual != deadline || delay != 2*time.Second || busyBody.closed != 1 || jar.Cookies(uri)[0].Value != "fixture-session" {
			t.Fatal("overview_query_backoff_or_session_changed")
		}
		// Even a separate jar change cannot change the session being retried.
		jar.SetCookies(uri, []*http.Cookie{{Name: "session", Value: "unrelated-session", Path: "/"}})
		return nil
	})
	if result.failure != "" || result.status != 200 || result.busy || !result.retried || calls != 2 || waits != 1 || !reflect.DeepEqual(page, expected) || completeMVPOverviewPageValid(view, "processes", view.Processes.Complete, page) != nil {
		t.Fatal("overview_query_bounded_page_retry_failed")
	}
}

func TestCompleteMVPOverviewQueryRejectsNonRetryableResponses(t *testing.T) {
	_, _, input, _ := completeMVPOverviewQueryFixture(t)
	for _, test := range []struct {
		name, raw, retry, failure string
		status                    int
	}{
		{"bad_request", completeMVPBusyJSON, "2", "status", 400},
		{"unauthorized", completeMVPBusyJSON, "2", "status", 401},
		{"forbidden", completeMVPBusyJSON, "2", "status", 403},
		{"not_found", completeMVPBusyJSON, "2", "status", 404},
		{"expired", completeMVPBusyJSON, "2", "status", 409},
		{"unavailable", completeMVPBusyJSON, "2", "status", 503},
		{"other_status", completeMVPBusyJSON, "2", "status", 418},
		{"redirect", completeMVPBusyJSON, "2", "status", 302},
		{"wrong_code", `{"error":{"code":"authentication_required","message":"fixture"}}`, "2", "status", 429},
		{"invalid_busy", `{"error":`, "2", "status", 429},
		{"duplicate_code", `{"error":{"code":"storage_busy","code":"storage_busy","message":"fixture"}}`, "2", "status", 429},
		{"aliased_code", `{"error":{"code":"authentication_required","Code":"storage_busy","message":"fixture"}}`, "2", "status", 429},
		{"aliased_outer", `{"Error":{"code":"storage_busy","message":"fixture"}}`, "2", "status", 429},
		{"duplicate_outer", `{"error":{"code":"authentication_required","message":"fixture"},"error":{"code":"storage_busy","message":"fixture"}}`, "2", "status", 429},
		{"extra_outer", `{"error":{"code":"storage_busy","message":"fixture"},"extra":true}`, "2", "status", 429},
		{"extra_inner", `{"error":{"code":"storage_busy","message":"fixture","extra":true}}`, "2", "status", 429},
		{"missing_message", `{"error":{"code":"storage_busy"}}`, "2", "status", 429},
		{"empty_message", `{"error":{"code":"storage_busy","message":""}}`, "2", "status", 429},
		{"null_message", `{"error":{"code":"storage_busy","message":null}}`, "2", "status", 429},
		{"nonstring_code", `{"error":{"code":429,"message":"fixture"}}`, "2", "status", 429},
		{"duplicate_message", `{"error":{"code":"storage_busy","message":"one","message":"two"}}`, "2", "status", 429},
		{"trailing_busy", completeMVPBusyJSON + `{}`, "2", "status", 429},
		{"oversized_busy", completeMVPBusyJSON + strings.Repeat(" ", 4096), "2", "status", 429},
		{"missing_backoff", completeMVPBusyJSON, "", "status", 429},
		{"wrong_backoff", completeMVPBusyJSON, "20", "status", 429},
		{"wrong_dto", `{"totalRows":"private-fixture-decode"}`, "", "decode", 200},
		{"unknown_field", `{"private-fixture-field":true}`, "", "decode", 200},
		{"trailing_dto", `{} {}`, "", "trailing", 200},
		{"trailing_invalid", `{} private-fixture-trailing`, "", "trailing", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
				calls++
				response := completeMVPOperatorResponse(test.status, test.raw, test.retry)
				response.Header.Set("Location", "http://fixture.invalid/api/auth/login")
				return response, nil
			})}
			page, result := completeMVPOverviewQueryRead(context.Background(), client, "http://fixture.invalid", "private-fixture-device", "private-fixture-csrf", input, func(context.Context, time.Duration) error { t.Fatal("overview_query_nonretryable_wait"); return nil })
			if calls != 1 || result.retried || result.busy || result.status != test.status || result.failure != test.failure || !reflect.DeepEqual(page, completeMVPOverviewPage{}) {
				t.Fatal("overview_query_nonretryable_response_hidden")
			}
			if strings.Contains(completeMVPOverviewQueryDiagnostic("private-fixture-section", result), "private-fixture") {
				t.Fatal("overview_query_private_diagnostic")
			}
		})
	}
}

func TestCompleteMVPOverviewQueryRejectsAmbiguousBackoff(t *testing.T) {
	_, _, input, _ := completeMVPOverviewQueryFixture(t)
	for _, header := range []http.Header{
		{"Retry-After": {"2", "2"}}, {"Retry-After": {"2", "20"}}, {"Retry-After": {"20", "2"}},
		{"Retry-After": {"2, 2"}}, {"Retry-After": {"2"}, "retry-after": {"2"}},
		{"Retry-After": {" 2"}}, {"Retry-After": {"02"}},
	} {
		calls := 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
			calls++
			response := completeMVPOperatorResponse(429, completeMVPBusyJSON, "")
			response.Header = header
			return response, nil
		})}
		_, result := completeMVPOverviewQueryRead(context.Background(), client, "http://fixture.invalid", "fixture-device", "fixture-csrf", input, func(context.Context, time.Duration) error { t.Fatal("overview_query_ambiguous_wait"); return nil })
		if calls != 1 || result.retried || result.busy || result.failure != "status" || result.status != 429 {
			t.Fatal("overview_query_ambiguous_backoff_retried")
		}
	}
}

func TestCompleteMVPOverviewQueryStopsAfterOneRetry(t *testing.T) {
	_, _, input, _ := completeMVPOverviewQueryFixture(t)
	for _, final := range []struct {
		status       int
		raw, failure string
		busy         bool
	}{{429, completeMVPBusyJSON, "status", true}, {401, completeMVPBusyJSON, "status", false}, {200, `{ "items": "invalid" }`, "decode", false}} {
		calls, waits := 0, 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
			}
			return completeMVPOperatorResponse(final.status, final.raw, "2"), nil
		})}
		_, result := completeMVPOverviewQueryRead(context.Background(), client, "http://fixture.invalid", "fixture-device", "fixture-csrf", input, func(context.Context, time.Duration) error { waits++; return nil })
		if calls != 2 || waits != 1 || !result.retried || result.busy != final.busy || result.failure != final.failure || result.status != final.status {
			t.Fatal("overview_query_attempt_bound_changed")
		}
	}
}

func TestCompleteMVPOverviewQueryCancellationAndParentDeadline(t *testing.T) {
	_, _, input, _ := completeMVPOverviewQueryFixture(t)
	for _, mode := range []string{"before_send", "during_wait", "after_wait", "wait_error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
			defer cancel()
			parentDeadline, _ := ctx.Deadline()
			if mode == "before_send" {
				cancel()
			}
			calls, waits := 0, 0
			client := &http.Client{Transport: completeMVPOperatorTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, _ := r.Context().Deadline()
				if deadline != parentDeadline {
					t.Fatal("overview_query_parent_deadline_extended")
				}
				return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
			})}
			_, result := completeMVPOverviewQueryRead(ctx, client, "http://fixture.invalid", "fixture-device", "fixture-csrf", input, func(waitCtx context.Context, _ time.Duration) error {
				waits++
				if mode == "wait_error" {
					return errors.New("private-fixture-wait")
				}
				cancel()
				if mode == "during_wait" {
					return completeMVPOperatorWait(waitCtx, 2*time.Second)
				}
				return nil
			})
			want := 1
			if mode == "before_send" {
				want = 0
			}
			if calls != want || waits != want || result.failure != "deadline" || result.retried != (want == 1) {
				t.Fatal("overview_query_cancellation_sent_again")
			}
		})
	}
}

type completeMVPOverviewQueryBody struct {
	io.Reader
	read, closed int
}

func (b *completeMVPOverviewQueryBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *completeMVPOverviewQueryBody) Close() error { b.closed++; return nil }

type completeMVPOverviewQueryBrokenReader struct{}

func (completeMVPOverviewQueryBrokenReader) Read([]byte) (int, error) {
	return 0, errors.New("private-fixture-body")
}

func TestCompleteMVPOverviewQueryBodyBoundsAndFailures(t *testing.T) {
	_, expected, input, raw := completeMVPOverviewQueryFixture(t)
	for _, test := range []struct {
		name, failure string
		reader        io.Reader
		read          int
	}{
		{"exact_limit", "", io.MultiReader(bytes.NewReader(raw), strings.NewReader(strings.Repeat(" ", completeMVPOverviewQueryLimit-len(raw)))), completeMVPOverviewQueryLimit},
		{"oversize", "oversize", strings.NewReader(strings.Repeat(" ", completeMVPOverviewQueryLimit+4096)), completeMVPOverviewQueryLimit + 1},
		{"body_error", "body", completeMVPOverviewQueryBrokenReader{}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &completeMVPOverviewQueryBody{Reader: test.reader}
			calls := 0
			client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
			})}
			page, result := completeMVPOverviewQueryRead(context.Background(), client, "http://fixture.invalid", "fixture-device", "fixture-csrf", input, func(context.Context, time.Duration) error { t.Fatal("overview_query_body_failure_wait"); return nil })
			if result.failure != test.failure || result.retried || body.read != test.read || body.closed != 1 || calls != 1 || (test.failure == "" && !reflect.DeepEqual(page, expected)) {
				t.Fatal("overview_query_body_contract_changed")
			}
		})
	}
}

func TestCompleteMVPOverviewQueryTransportAndDiagnosticPrivacy(t *testing.T) {
	_, _, input, _ := completeMVPOverviewQueryFixture(t)
	for _, initialBusy := range []bool{false, true} {
		calls := 0
		client := &http.Client{Transport: completeMVPOperatorTransport(func(*http.Request) (*http.Response, error) {
			calls++
			if initialBusy && calls == 1 {
				return completeMVPOperatorResponse(429, completeMVPBusyJSON, "2"), nil
			}
			return nil, errors.New("private-fixture-transport")
		})}
		_, result := completeMVPOverviewQueryRead(context.Background(), client, "http://fixture.invalid", "private-fixture-device", "private-fixture-csrf", input, func(context.Context, time.Duration) error { return nil })
		wantCalls := 1
		if initialBusy {
			wantCalls = 2
		}
		if result.failure != "transport" || result.status != 0 || result.busy || result.retried != initialBusy || calls != wantCalls {
			t.Fatal("overview_query_transport_retried_or_stale_status")
		}
		if completeMVPOverviewQueryDiagnostic("volumes", result) != "complete operator overview query diagnostic: section=volumes status=none failure=transport storage_busy=false" {
			t.Fatal("overview_query_transport_diagnostic_changed")
		}
	}
	if completeMVPOverviewQueryDiagnostic("private-fixture-section", completeMVPOverviewQueryResult{status: 12345, failure: "private-fixture-error", busy: true}) != "complete operator overview query diagnostic: section=other status=http_other failure=other storage_busy=true" {
		t.Fatal("overview_query_diagnostic_not_finite")
	}
}
