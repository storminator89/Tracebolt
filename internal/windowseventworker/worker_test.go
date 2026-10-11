package windowseventworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
)

func requestFixtureAt(t *testing.T, created time.Time) Request {
	t.Helper()
	created = created.UTC().Truncate(100 * time.Nanosecond)
	consent := windowseventrequest.Consent{
		SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope,
		SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32),
		Profile: "tls", Enabled: true, ContentAcknowledged: true,
	}
	local := windowseventrequest.LocalContext{
		SenderBinding: consent.SenderBinding, Profile: consent.Profile,
		DeviceID: "agent_" + strings.Repeat("c", 32), CertificateHash: strings.Repeat("d", 64),
	}
	headers := windowseventhealth.Snapshot{
		SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope,
		GrantID: strings.Repeat("e", 32), GenerationID: "sample_" + strings.Repeat("f", 32),
		CollectedAt: created.Add(-time.Second), Channels: []windowseventhealth.Channel{
			{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1,
				Rows: []windowseventhealth.Event{{RecordID: "18446744073709551615", EventID: 1, Level: 2, Provider: "Synthetic fixture", Timestamp: created.Add(-2 * time.Second)}}},
			{Channel: "System", Quality: "observed", Complete: true, ObservedCount: 1,
				Rows: []windowseventhealth.Event{{RecordID: "42", EventID: 2, Level: 3, Provider: "Synthetic fixture", Timestamp: created.Add(-3 * time.Second)}}},
		},
	}
	record, err := windowseventrequest.New(local.DeviceID, local.CertificateHash, 1, consent.GrantID, headers,
		[]windowseventrequest.Selection{{Channel: "Application", RecordID: "18446744073709551615"}, {Channel: "System", RecordID: "42"}}, created)
	if err != nil {
		t.Fatal("invalid fixture description")
	}
	claimedAt := created.Add(time.Millisecond)
	policy, err := windowseventrequest.Authorize(record.Description, consent, local, claimedAt)
	if err != nil {
		t.Fatal("invalid fixture authorization")
	}
	return Request{Description: record.Description, PolicyDigest: policy, ClaimedAt: claimedAt, Local: local, Consent: consent}
}

func requestFixture(t *testing.T) Request {
	t.Helper()
	return requestFixtureAt(t, time.Now().UTC().Add(-time.Second))
}

func reportFixture(req Request) windowseventcontent.Report {
	report := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning,
		Quality: windowseventcontent.QualityObserved, CollectedAt: time.Now().UTC(), Complete: true}
	for _, event := range req.Description.Query.Events {
		report.Events = append(report.Events, windowseventcontent.Result{Event: event, Message: "synthetic-only-message",
			Quality: windowseventcontent.QualityObserved, Complete: true})
	}
	return report
}

func resolveFixture(_ context.Context, req Request) (Request, error) { return req, nil }
func consumeFixture(context.Context, Request) error                  { return nil }
func readFixture(_ context.Context, req Request) (windowseventcontent.Report, error) {
	return reportFixture(req), nil
}

func mustEncodeRequest(t *testing.T, req Request) []byte {
	t.Helper()
	raw, err := encodeRequest(req)
	if err != nil {
		t.Fatal("request encoding failed: ", err)
	}
	return raw
}

func TestRequestCanonicalBoundedAndRedacted(t *testing.T) {
	req := requestFixture(t)
	raw := mustEncodeRequest(t, req)
	decoded, err := decodeRequest(raw)
	if err != nil || !sameRequest(req, decoded) || decoded.Description.Query.Events[0].RecordID != ^uint64(0) {
		t.Fatal("canonical/full-width selection round trip failed")
	}
	bad := [][]byte{
		nil, []byte("{}"), bytes.Repeat([]byte{'x'}, maxRequestBytes+1),
		append(append([]byte{}, raw...), '\n'), append(append([]byte{}, raw...), raw...),
		bytes.Replace(raw, []byte(`"description":`), []byte(`"configPath":"private","description":`), 1),
		bytes.Replace(raw, []byte(`"policyDigest":`), []byte(`"policyDigest":"`+req.PolicyDigest+`","policyDigest":`), 1),
		bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1),
		bytes.Replace(raw, []byte(`"record_id":18446744073709551615`), []byte(`"record_id":18446744073709551616`), 1),
		bytes.Replace(raw, []byte(`"profile":"tls"`), []byte(`"profile":"TLS"`), 1),
	}
	for i, invalid := range bad {
		if _, err := decodeRequest(invalid); err == nil {
			t.Errorf("invalid canonical request %d accepted", i)
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if got := fmt.Sprintf(verb, req); got != "<windows-event-worker request redacted>" {
			t.Fatal("request leaked diagnostic metadata")
		}
	}
}

func TestInvalidRequestsNeverConstructProcess(t *testing.T) {
	mutations := map[string]func(*Request){
		"disabled":            func(r *Request) { r.Consent.Enabled = false },
		"absent":              func(r *Request) { r.Consent = windowseventrequest.Consent{} },
		"foreign local":       func(r *Request) { r.Local.DeviceID = "agent_" + strings.Repeat("e", 32) },
		"foreign certificate": func(r *Request) { r.Local.CertificateHash = strings.Repeat("e", 64) },
		"foreign sender":      func(r *Request) { r.Local.SenderBinding = strings.Repeat("e", 64) },
		"foreign profile":     func(r *Request) { r.Local.Profile = "http-test" },
		"acknowledgement":     func(r *Request) { r.Consent.ContentAcknowledged = false },
		"policy":              func(r *Request) { r.PolicyDigest = "sha256:" + strings.Repeat("0", 64) },
		"empty claim":         func(r *Request) { r.ClaimedAt = time.Time{} },
		"before creation":     func(r *Request) { r.ClaimedAt = r.Description.CreatedAt.Add(-time.Second) },
		"future claim":        func(r *Request) { r.ClaimedAt = time.Now().UTC().Add(time.Second) },
		"expiry claim":        func(r *Request) { r.ClaimedAt = r.Description.ExpiresAt },
		"non utc":             func(r *Request) { r.ClaimedAt = r.ClaimedAt.In(time.FixedZone("offset", 3600)) },
		"query":               func(r *Request) { r.Description.Query.Events[0].Channel = "Security" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			req := requestFixture(t)
			mutate(&req)
			_, err := gather(context.Background(), req, time.Second, func(context.Context) (*exec.Cmd, error) {
				t.Fatal("invalid request constructed a process")
				return nil, nil
			})
			if err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	expired := requestFixtureAt(t, time.Now().UTC().Add(-windowseventrequest.Lifetime-time.Second))
	_, err := gather(context.Background(), expired, time.Second, func(context.Context) (*exec.Cmd, error) {
		t.Fatal("expired request constructed a process")
		return nil, nil
	})
	if !errors.Is(err, windowseventrequest.ErrExpired) {
		t.Fatal("expiry did not fail closed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = gather(ctx, requestFixture(t), time.Second, func(context.Context) (*exec.Cmd, error) {
		t.Fatal("canceled request constructed a process")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation lost")
	}
}

func TestFixedCurrentExecutable(t *testing.T) {
	command, err := newWorkerCommand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != executable || !reflect.DeepEqual(command.Args, []string{executable, WorkerArgument}) || command.Dir != filepath.Dir(executable) {
		t.Fatal("worker executable, argument or directory is configurable")
	}
	if WorkerBudget != 10*time.Second || MaxResponseBytes != 512<<10 {
		t.Fatal("fixed worker bounds changed")
	}
}

func TestServeConsumesBeforeReadAndRechecksAfter(t *testing.T) {
	req := requestFixture(t)
	var order []string
	var out bytes.Buffer
	err := Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, req)), &out,
		func(_ context.Context, r Request) (Request, error) { order = append(order, "verify"); return r, nil },
		func(context.Context, Request) error { order = append(order, "consume"); return nil },
		func(ctx context.Context, r Request) (windowseventcontent.Report, error) {
			order = append(order, "read")
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > windowseventcontent.CollectionTimeout || time.Until(deadline) <= 0 {
				t.Fatal("reader did not receive the fixed cooperative budget")
			}
			return reportFixture(r), nil
		})
	if err != nil || !reflect.DeepEqual(order, []string{"verify", "consume", "read", "verify"}) {
		t.Fatalf("incorrect order or failure: %v %v", order, err)
	}
	if _, err := decodeResponse(out.Bytes(), req, time.Now().UTC()); err != nil {
		t.Fatal("response was not exactly bound")
	}
}

func TestServeConsumeFailureAndReplayNeverRead(t *testing.T) {
	req := requestFixture(t)
	raw := mustEncodeRequest(t, req)
	var mu sync.Mutex
	used, reads := false, 0
	consume := func(context.Context, Request) error {
		mu.Lock()
		defer mu.Unlock()
		if used {
			return windowseventrequest.ErrConsumed
		}
		used = true // Synthetic committed floor, not a real installed-state write.
		return nil
	}
	for call := 0; call < 2; call++ {
		var out bytes.Buffer
		err := Serve(context.Background(), bytes.NewReader(raw), &out, resolveFixture, consume,
			func(_ context.Context, r Request) (windowseventcontent.Report, error) {
				if !used {
					t.Fatal("reader ran before committed consumption")
				}
				reads++
				return reportFixture(r), nil
			})
		if call == 0 && (err != nil || out.Len() == 0) || call == 1 && (!errors.Is(err, windowseventrequest.ErrConsumed) || out.Len() != 0) {
			t.Fatal("consume/replay semantics lost")
		}
	}
	if reads != 1 {
		t.Fatal("replay recaptured content")
	}
	for _, failure := range []error{windowseventrequest.ErrConsumed, errors.New("private state path failed")} {
		var out bytes.Buffer
		err := Serve(context.Background(), bytes.NewReader(raw), &out, resolveFixture,
			func(context.Context, Request) error { return failure },
			func(context.Context, Request) (windowseventcontent.Report, error) {
				t.Fatal("failed/ambiguous consume reached reader")
				return windowseventcontent.Report{}, nil
			})
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "private") {
			t.Fatal("consume failure leaked or emitted content")
		}
	}
}

func TestServeRejectsAuthorityChangesBeforeAndAfter(t *testing.T) {
	for _, when := range []int{1, 2} {
		for name, mutate := range map[string]func(*Request) error{
			"absent":      func(*Request) error { return windowseventrequest.ErrDisabled },
			"raw error":   func(*Request) error { return errors.New("private identity failure") },
			"disabled":    func(r *Request) error { r.Consent.Enabled = false; return nil },
			"grant":       func(r *Request) error { r.Consent.GrantID = strings.Repeat("f", 32); return nil },
			"sender":      func(r *Request) error { r.Local.SenderBinding = strings.Repeat("f", 64); return nil },
			"certificate": func(r *Request) error { r.Local.CertificateHash = strings.Repeat("f", 64); return nil },
			"device":      func(r *Request) error { r.Local.DeviceID = "agent_" + strings.Repeat("f", 32); return nil },
			"policy":      func(r *Request) error { r.PolicyDigest = "sha256:" + strings.Repeat("f", 64); return nil },
			"claim":       func(r *Request) error { r.ClaimedAt = r.ClaimedAt.Add(time.Nanosecond); return nil },
			"selection":   func(r *Request) error { r.Description.Query.Events[0].Provider = "Changed fixture"; return nil },
		} {
			t.Run(fmt.Sprintf("%s-%d", name, when), func(t *testing.T) {
				req := requestFixture(t)
				checks, consumes, reads := 0, 0, 0
				var out bytes.Buffer
				err := Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, req)), &out,
					func(_ context.Context, r Request) (Request, error) {
						checks++
						if checks == when {
							err := mutate(&r)
							return r, err
						}
						return r, nil
					},
					func(context.Context, Request) error { consumes++; return nil },
					func(_ context.Context, r Request) (windowseventcontent.Report, error) {
						reads++
						return reportFixture(r), nil
					})
				if err == nil || out.Len() != 0 || checks != when || consumes != when-1 || reads != when-1 || strings.Contains(err.Error(), "private") {
					t.Fatal("changed authority leaked content or reached an unauthorized read")
				}
			})
		}
	}
}

func TestServePartialSourceErrorSurvivesAndRawErrorsDoNot(t *testing.T) {
	req := requestFixture(t)
	for _, quality := range []string{windowseventcontent.QualityPartial, windowseventcontent.QualityUnavailable} {
		var out bytes.Buffer
		checks := 0
		err := Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, req)), &out,
			func(_ context.Context, r Request) (Request, error) { checks++; return r, nil }, consumeFixture,
			func(_ context.Context, r Request) (windowseventcontent.Report, error) {
				report := reportFixture(r)
				report.Quality, report.Complete = quality, false
				for i := range report.Events {
					if quality == windowseventcontent.QualityPartial && i == 0 {
						continue
					}
					report.Events[i].Message, report.Events[i].Complete = "", false
					report.Events[i].Quality, report.Events[i].Reason = windowseventcontent.QualityUnavailable, windowseventcontent.ErrNotFound.Error()
				}
				return report, errors.New("private publisher resource path and raw source error")
			})
		if err != nil || checks != 2 || strings.Contains(out.String(), "private publisher") {
			t.Fatal("valid partial/error handling failed")
		}
		report, err := decodeResponse(out.Bytes(), req, time.Now().UTC())
		if err != nil || report.Quality != quality || quality == windowseventcontent.QualityPartial && report.Events[0].Message == "" {
			t.Fatal("successful row was lost")
		}
	}
}

func TestServeInvalidReportsNeverEmitContent(t *testing.T) {
	for name, mutate := range map[string]func(*windowseventcontent.Report, Request){
		"foreign selection": func(r *windowseventcontent.Report, _ Request) { r.Events[0].Event.RecordID++ },
		"before claim":      func(r *windowseventcontent.Report, req Request) { r.CollectedAt = req.ClaimedAt.Add(-time.Nanosecond) },
		"after now":         func(r *windowseventcontent.Report, _ Request) { r.CollectedAt = time.Now().UTC().Add(time.Hour) },
		"at expiry":         func(r *windowseventcontent.Report, req Request) { r.CollectedAt = req.Description.ExpiresAt },
		"raw reason":        func(r *windowseventcontent.Report, _ Request) { r.Events[0].Reason = "private OS path" },
		"invalid shape":     func(r *windowseventcontent.Report, _ Request) { *r = windowseventcontent.Report{} },
	} {
		t.Run(name, func(t *testing.T) {
			req := requestFixture(t)
			checks := 0
			var out bytes.Buffer
			err := Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, req)), &out,
				func(_ context.Context, r Request) (Request, error) { checks++; return r, nil }, consumeFixture,
				func(_ context.Context, r Request) (windowseventcontent.Report, error) {
					report := reportFixture(r)
					mutate(&report, r)
					return report, errors.New("private source error")
				})
			if !errors.Is(err, ErrMetadata) || checks != 2 || out.Len() != 0 {
				t.Fatal("invalid result bypassed final authority or response validation")
			}
		})
	}
}

func TestServeCallbackCannotMutateOriginalSelection(t *testing.T) {
	req := requestFixture(t)
	var out bytes.Buffer
	err := Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, req)), &out, resolveFixture,
		func(_ context.Context, r Request) error {
			r.Description.Query.Events[0].Provider = "consume-only mutation"
			return nil
		},
		func(_ context.Context, r Request) (windowseventcontent.Report, error) {
			if r.Description.Query.Events[0].Provider != req.Description.Query.Events[0].Provider {
				t.Fatal("consume mutated the authoritative query")
			}
			r.Description.Query.Events[0].Provider = "reader mutation"
			return reportFixture(r), nil
		})
	if !errors.Is(err, ErrMetadata) || out.Len() != 0 {
		t.Fatal("reader mutation changed the authoritative query")
	}
}

type countedInput struct {
	reader io.Reader
	count  int
}

func (r *countedInput) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += n
	return n, err
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) - 1, nil }

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("private output failure") }

func TestServeMalformedAndBoundedIO(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{'x'}, maxRequestBytes*4)} {
		input := &countedInput{reader: bytes.NewReader(raw)}
		var out bytes.Buffer
		err := Serve(context.Background(), input, &out,
			func(context.Context, Request) (Request, error) {
				t.Fatal("malformed request reached authority")
				return Request{}, nil
			}, consumeFixture, readFixture)
		if err == nil || out.Len() != 0 || input.count > maxRequestBytes+1 {
			t.Fatal("malformed input was not bounded/rejected")
		}
	}
	raw := mustEncodeRequest(t, requestFixture(t))
	if err := Serve(context.Background(), bytes.NewReader(raw), shortOutput{}, resolveFixture, consumeFixture, readFixture); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short output accepted")
	}
	if err := Serve(context.Background(), bytes.NewReader(raw), failedOutput{}, resolveFixture, consumeFixture, readFixture); !errors.Is(err, ErrUnavailable) {
		t.Fatal("private output error was exposed")
	}
	canceled := 0
	output := boundedOutput{cancel: func() { canceled++ }}
	if _, err := output.Write(bytes.Repeat([]byte{'a'}, MaxResponseBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{'b'}); !errors.Is(err, ErrBounds) || canceled != 1 || !output.exceeded || output.Len() != MaxResponseBytes {
		t.Fatal("overflow was retained or did not cancel child")
	}
	var asAny any = &output
	if _, bypass := asAny.(io.ReaderFrom); bypass {
		t.Fatal("ReaderFrom bypasses output limit")
	}
}

func TestResponseCanonicalAndExactlyBound(t *testing.T) {
	req := requestFixture(t)
	report := reportFixture(req)
	raw, err := encodeResponse(report, req, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte{}, raw...), '\n'),
		bytes.Replace(raw, []byte(`"policyDigest":`), []byte(`"config":"private","policyDigest":`), 1),
		bytes.Replace(raw, []byte(`"policyDigest":`), []byte(`"policyDigest":"`+req.PolicyDigest+`","policyDigest":`), 1),
	} {
		if _, err := decodeResponse(invalid, req, time.Now().UTC()); !errors.Is(err, ErrMetadata) {
			t.Fatal("noncanonical response accepted")
		}
	}
	for name, mutate := range map[string]func(*wireResponse){
		"identity": func(r *wireResponse) { r.Identity.Sequence++ },
		"policy":   func(r *wireResponse) { r.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
		"claim":    func(r *wireResponse) { r.ClaimedAt = r.ClaimedAt.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			var wire wireResponse
			if json.Unmarshal(raw, &wire) != nil {
				t.Fatal("fixture response decode failed")
			}
			mutate(&wire)
			invalid, _ := json.Marshal(wire)
			if _, err := decodeResponse(invalid, req, time.Now().UTC()); !errors.Is(err, ErrMetadata) {
				t.Fatal("foreign response binding accepted")
			}
		})
	}
}

// TestWorkerFixture invokes only inert synthetic child behavior. It never reads
// native logs, installed state, host identity or real protected grant receipts.
func TestWorkerFixture(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "worker-fixture:") {
		return
	}
	mode = strings.TrimPrefix(mode, "worker-fixture:")
	if mode == "pipe-holder" {
		time.Sleep(800 * time.Millisecond)
		os.Exit(0)
	}
	if mode == "inherited-pipe" {
		executable, err := os.Executable()
		if err != nil {
			os.Exit(93)
		}
		holder := exec.Command(executable, "-test.run=^TestWorkerFixture$", "--", "worker-fixture:pipe-holder")
		holder.Env, err = workerEnvironment()
		if err != nil {
			os.Exit(94)
		}
		holder.Stdout = os.Stdout
		if holder.Start() != nil {
			os.Exit(95)
		}
		_ = holder.Process.Release()
	}
	if mode == "blocked" || mode == "never-read" {
		time.Sleep(time.Hour)
		os.Exit(90)
	}
	if mode == "overflow" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, MaxResponseBytes+1))
		time.Sleep(time.Hour)
		os.Exit(91)
	}
	if mode == "malformed" {
		_, _ = os.Stdout.Write([]byte("not a report"))
		os.Exit(0)
	}
	if mode == "environment" {
		for _, value := range os.Environ() {
			if runtime.GOOS != "windows" || !strings.HasPrefix(value, "SystemRoot=") {
				os.Exit(92)
			}
		}
	}
	checks, consumed := 0, false
	err := Serve(context.Background(), os.Stdin, os.Stdout,
		func(_ context.Context, req Request) (Request, error) {
			checks++
			if mode == "denied" || mode == "revoked" && checks == 2 {
				return Request{}, windowseventrequest.ErrDisabled
			}
			return req, nil
		},
		func(context.Context, Request) error {
			if mode == "consumed" {
				return windowseventrequest.ErrConsumed
			}
			consumed = true
			return nil
		},
		func(_ context.Context, req Request) (windowseventcontent.Report, error) {
			if !consumed || mode == "denied" || mode == "consumed" {
				os.Exit(99)
			}
			report := reportFixture(req)
			if mode == "rebound" {
				report.Events[0].Event.RecordID++
			}
			if mode == "partial" {
				report.Quality, report.Complete = windowseventcontent.QualityPartial, false
				report.Events[1].Quality, report.Events[1].Complete, report.Events[1].Message = windowseventcontent.QualityUnavailable, false, ""
				report.Events[1].Reason = windowseventcontent.ErrNotFound.Error()
				return report, errors.New("private reader failure")
			}
			return report, nil
		})
	if err != nil {
		if errors.Is(err, windowseventrequest.ErrDisabled) {
			os.Exit(31)
		}
		if errors.Is(err, windowseventrequest.ErrConsumed) {
			os.Exit(33)
		}
		os.Exit(32)
	}
	os.Exit(0)
}

func fixtureFactory(t *testing.T, mode string, child **exec.Cmd) commandFactory {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context) (*exec.Cmd, error) {
		command := exec.CommandContext(ctx, executable, "-test.run=^TestWorkerFixture$", "--", "worker-fixture:"+mode)
		*child = command
		return command, nil
	}
}
func childReaped(child *exec.Cmd) bool {
	// Cmd.Wait records ProcessState only after Process.Wait returns. Exited is
	// not suitable here: a signal-killed Unix child reports Exited() == false.
	if child == nil || child.Process == nil || child.ProcessState == nil ||
		child.Process.Pid <= 0 || child.ProcessState.Pid() != child.Process.Pid {
		return false
	}
	// Wait releases the process handle. Do not probe with Kill: Windows marks
	// a waited process released and returns EINVAL, rather than ErrProcessDone.
	// WithHandle must not expose a usable handle after Wait on either platform.
	handleAvailable := false
	err := child.Process.WithHandle(func(uintptr) { handleAvailable = true })
	return err != nil && !handleAvailable
}

func assertReaped(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if !childReaped(child) {
		t.Fatal("child was not synchronously waited or retained a usable process handle")
	}
}

func TestReapedAssertionRejectsLiveAndUnwaitedChild(t *testing.T) {
	if childReaped(nil) || childReaped(&exec.Cmd{}) {
		t.Fatal("unstarted child was reported reaped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var child *exec.Cmd
	command, err := fixtureFactory(t, "blocked", &child)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	command.Env, err = workerEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if command.ProcessState == nil {
			_ = command.Wait()
		}
	})
	if childReaped(child) {
		t.Fatal("live child was reported reaped")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if childReaped(child) {
		t.Fatal("killed but unwaited child was reported reaped")
	}
	var exit *exec.ExitError
	if err := command.Wait(); !errors.As(err, &exit) {
		t.Fatalf("blocked child did not report its killed exit: %v", err)
	}
	assertReaped(t, child)
}

func TestSubprocessBudgetAndExpiryKillAndReap(t *testing.T) {
	for _, mode := range []string{"blocked", "never-read", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			req := requestFixture(t)
			budget, want := 250*time.Millisecond, ErrBudget
			childMode := mode
			if mode == "expiry" {
				req = requestFixtureAt(t, time.Now().UTC().Add(-windowseventrequest.Lifetime+250*time.Millisecond))
				budget, want, childMode = 10*time.Second, windowseventrequest.ErrExpired, "blocked"
			}
			var child *exec.Cmd
			start := time.Now()
			report, err := gather(context.Background(), req, budget, fixtureFactory(t, childMode, &child))
			if !errors.Is(err, want) || !reflect.DeepEqual(report, windowseventcontent.Report{}) {
				t.Fatal("budget/expiry did not fail closed: ", err)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("blocked child delayed parent")
			}
			assertReaped(t, child)
		})
	}
}

func TestSubprocessCallerCancellationKillsAndReaps(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		want := context.DeadlineExceeded
		if !deadline {
			cancel()
			ctx, cancel = context.WithCancel(context.Background())
			stop := time.AfterFunc(250*time.Millisecond, cancel)
			defer stop.Stop()
			want = context.Canceled
		}
		var child *exec.Cmd
		report, err := gather(ctx, requestFixture(t), 10*time.Second, fixtureFactory(t, "blocked", &child))
		cancel()
		if !errors.Is(err, want) || !reflect.DeepEqual(report, windowseventcontent.Report{}) {
			t.Fatal("caller cancellation lost")
		}
		assertReaped(t, child)
	}
}

func TestSubprocessInheritedPipeDoesNotStallWait(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process-lifetime fixture")
	}
	var child *exec.Cmd
	start := time.Now()
	report, err := gather(context.Background(), requestFixture(t), 10*time.Second, fixtureFactory(t, "inherited-pipe", &child))
	// The inert descendant has a finite 800ms lifetime plus race exit delay.
	defer time.Sleep(2 * time.Second)
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, windowseventcontent.Report{}) {
		t.Fatal("inherited pipe was not rejected")
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("WaitDelay failed to bound descendant pipe")
	}
	assertReaped(t, child)
	if child.WaitDelay != pipeWaitDelay {
		t.Fatal("pipe wait bound missing")
	}
}

func TestSubprocessResponsesAndEnvironment(t *testing.T) {
	t.Setenv("TRACEBOLT_WORKER_PRIVATE_TEST_SECRET", "must-not-reach-child")
	for _, tc := range []struct {
		mode    string
		want    error
		quality string
	}{
		{"success", nil, windowseventcontent.QualityObserved},
		{"environment", nil, windowseventcontent.QualityObserved},
		{"partial", nil, windowseventcontent.QualityPartial},
		{"overflow", ErrBounds, ""}, {"malformed", ErrMetadata, ""},
		{"rebound", ErrUnavailable, ""}, {"denied", ErrUnavailable, ""},
		{"revoked", ErrUnavailable, ""}, {"consumed", ErrUnavailable, ""},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			req := requestFixture(t)
			var child *exec.Cmd
			report, err := gather(context.Background(), req, WorkerBudget, fixtureFactory(t, tc.mode, &child))
			if !errors.Is(err, tc.want) || report.Quality != tc.quality {
				t.Fatal("unexpected subprocess response: ", err)
			}
			assertReaped(t, child)
			if (tc.mode == "denied" || tc.mode == "revoked") && child.ProcessState.ExitCode() != 31 || tc.mode == "consumed" && child.ProcessState.ExitCode() != 33 {
				t.Fatal("authority/consumption failure reached source or emitted output")
			}
			if child.Stderr != nil {
				t.Fatal("stderr was not discarded")
			}
			reader, ok := child.Stdin.(*bytes.Reader)
			if !ok {
				t.Fatal("stdin is not finite canonical memory")
			}
			if _, err := reader.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(raw, mustEncodeRequest(t, req)) {
				t.Fatal("unexpected child input")
			}
		})
	}
}

func TestProcessStartupFailureNeverExposesRawError(t *testing.T) {
	report, err := gather(context.Background(), requestFixture(t), time.Second,
		func(context.Context) (*exec.Cmd, error) { return nil, errors.New("private executable path") })
	if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(report, windowseventcontent.Report{}) {
		t.Fatal("process failure exposed data or fabricated a report")
	}
}

func TestFailureAfterConsumptionDoesNotPermitRecapture(t *testing.T) {
	req := requestFixture(t)
	raw := mustEncodeRequest(t, req)
	used, reads := false, 0
	consume := func(context.Context, Request) error {
		if used {
			return windowseventrequest.ErrConsumed
		}
		used = true
		return nil
	}
	for call := 0; call < 2; call++ {
		var out bytes.Buffer
		err := Serve(context.Background(), bytes.NewReader(raw), &out, resolveFixture, consume,
			func(context.Context, Request) (windowseventcontent.Report, error) {
				reads++
				return windowseventcontent.Report{}, errors.New("private native error")
			})
		want := ErrMetadata
		if call == 1 {
			want = windowseventrequest.ErrConsumed
		}
		if !errors.Is(err, want) || out.Len() != 0 {
			t.Fatal("failed capture released or reopened content")
		}
	}
	if reads != 1 {
		t.Fatal("a consumed failed request was recaptured")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	err := Serve(ctx, bytes.NewReader(raw), &out, resolveFixture,
		func(context.Context, Request) error { cancel(); return nil },
		func(context.Context, Request) (windowseventcontent.Report, error) {
			t.Fatal("cancellation between commit and source still read")
			return windowseventcontent.Report{}, nil
		})
	if !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancellation after consume not respected")
	}
}

func TestMaximumEscapedMessageBudgetFitsOutputBound(t *testing.T) {
	req := requestFixture(t)
	// A four-row report uses every permitted message byte. Each control byte
	// expands to six JSON bytes; the process cap must retain this valid result.
	for len(req.Description.Query.Events) < 4 {
		row := req.Description.Query.Events[1]
		row.RecordID += uint64(len(req.Description.Query.Events))
		req.Description.Query.Events = append(req.Description.Query.Events, row)
	}
	headers := windowseventhealth.Snapshot{
		SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope,
		GrantID: strings.Repeat("e", 32), GenerationID: req.Description.HeaderGenerationID,
		CollectedAt: req.Description.HeaderCollectedAt,
		Channels: []windowseventhealth.Channel{
			{Channel: "Application", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}},
			{Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}},
		},
	}
	var selections []windowseventrequest.Selection
	for _, event := range req.Description.Query.Events {
		recordID := strconv.FormatUint(event.RecordID, 10)
		selections = append(selections, windowseventrequest.Selection{Channel: event.Channel, RecordID: recordID})
		for i := range headers.Channels {
			if headers.Channels[i].Channel == event.Channel {
				headers.Channels[i].ObservedCount++
				headers.Channels[i].Rows = append(headers.Channels[i].Rows, windowseventhealth.Event{
					RecordID: recordID, EventID: event.EventID, Level: event.Level, Provider: event.Provider, Timestamp: event.Timestamp,
				})
			}
		}
	}
	record, err := windowseventrequest.New(req.Local.DeviceID, req.Local.CertificateHash, 1, req.Consent.GrantID, headers, selections, req.Description.CreatedAt)
	if err != nil {
		t.Fatal("maximum-report request fixture rejected")
	}
	req.Description = record.Description
	if validateRequest(req, time.Now().UTC()) != nil {
		t.Fatal("maximum-report request authority invalid")
	}
	report := reportFixture(req)
	for i := range report.Events {
		report.Events[i].Message = strings.Repeat("\x01", windowseventcontent.MaxMessageBytes)
	}
	raw, err := encodeResponse(report, req, time.Now().UTC())
	if err != nil || len(raw) <= windowseventcontent.MaxTotalMessageBytes*6 || len(raw) >= MaxResponseBytes {
		t.Fatal("valid maximally escaped report did not fit fixed IPC limit")
	}
	decoded, err := decodeResponse(raw, req, time.Now().UTC())
	if err != nil || len(decoded.Events) != 4 || !decoded.Complete {
		t.Fatal("maximally escaped report was lost")
	}
}
