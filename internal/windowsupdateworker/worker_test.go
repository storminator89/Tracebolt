package windowsupdateworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsupdates"
)

func requestFixture() windowsupdates.Request {
	binding := strings.Repeat("a", 64)
	return windowsupdates.Request{
		Consent: windowsupdates.Consent{
			SchemaVersion: windowsupdates.ConsentVersion, Scope: windowsupdates.Scope,
			SenderBinding: binding, GrantID: strings.Repeat("b", 32), Enabled: true,
		},
		SenderBinding: binding, GenerationID: "sample_" + strings.Repeat("c", 32),
		CollectedAt: time.Date(2026, 10, 10, 12, 34, 56, 123456789, time.UTC),
	}
}

func snapshotFixture(req windowsupdates.Request) windowsupdates.Snapshot {
	snapshot := emptySnapshot(req, "")
	snapshot.Quality = "observed"
	snapshot.CountExact = true
	return snapshot
}

func resolveFixture(_ context.Context, req windowsupdates.Request) (windowsupdates.Request, error) {
	return req, nil
}

func TestRequestCanonicalAndBounded(t *testing.T) {
	req := requestFixture()
	raw, err := encodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRequest(raw)
	if err != nil || !sameRequest(req, got) {
		t.Fatalf("round trip: %v", err)
	}
	want := `{"senderBinding":"` + req.SenderBinding + `","grantId":"` + req.Consent.GrantID + `","generationId":"` + req.GenerationID + `","collectedAt":"2026-10-10T12:34:56.123456789Z"}`
	if string(raw) != want {
		t.Fatal("unexpected request fields or canonical bytes")
	}
	bad := [][]byte{
		nil, []byte("{}"), bytes.Repeat([]byte("x"), maxRequestBytes+1),
		append(append([]byte{}, raw...), '\n'), append(append([]byte{}, raw...), raw...),
		bytes.Replace(raw, []byte(`"grantId":`), []byte(`"unknown":1,"grantId":`), 1),
		bytes.Replace(raw, []byte(`"grantId":`), []byte(`"grantId":"`+req.Consent.GrantID+`","grantId":`), 1),
		bytes.Replace(raw, []byte(`"collectedAt":`), []byte(`"configPath":"private","collectedAt":`), 1),
		bytes.Replace(raw, []byte(".123456789Z"), []byte(".123456789+00:00"), 1),
	}
	for i, invalid := range bad {
		if _, err := decodeRequest(invalid); err == nil {
			t.Errorf("invalid request %d accepted", i)
		}
	}
}

func TestInvalidRequestNeverStartsProcess(t *testing.T) {
	for name, mutate := range map[string]func(*windowsupdates.Request){
		"absent grant":    func(r *windowsupdates.Request) { r.Consent = windowsupdates.Consent{} },
		"disabled grant":  func(r *windowsupdates.Request) { r.Consent.Enabled = false },
		"foreign binding": func(r *windowsupdates.Request) { r.SenderBinding = strings.Repeat("d", 64) },
		"wrong scope":     func(r *windowsupdates.Request) { r.Consent.Scope = "windows-inventory" },
		"generation":      func(r *windowsupdates.Request) { r.GenerationID = "arbitrary" },
		"capture":         func(r *windowsupdates.Request) { r.CollectedAt = time.Time{} },
		"non utc":         func(r *windowsupdates.Request) { r.CollectedAt = r.CollectedAt.In(time.FixedZone("offset", 3600)) },
	} {
		t.Run(name, func(t *testing.T) {
			req := requestFixture()
			mutate(&req)
			started := false
			_, err := collect(context.Background(), req, time.Second, func(context.Context) (*exec.Cmd, error) {
				started = true
				return nil, nil
			})
			if err == nil || started {
				t.Fatal("invalid request reached process constructor")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collect(ctx, requestFixture(), time.Second, func(context.Context) (*exec.Cmd, error) {
		t.Fatal("canceled request started child")
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
		t.Fatal("worker executable, argument or directory was not fixed")
	}
}

func TestServeRevalidatesBeforeAndAfterNative(t *testing.T) {
	req := requestFixture()
	raw, _ := encodeRequest(req)
	var order []string
	var output bytes.Buffer
	err := Serve(context.Background(), bytes.NewReader(raw), &output,
		func(_ context.Context, r windowsupdates.Request) (windowsupdates.Request, error) {
			order = append(order, "verify")
			return r, nil
		},
		func(_ context.Context, r windowsupdates.Request) (windowsupdates.Snapshot, error) {
			order = append(order, "native")
			return snapshotFixture(r), nil
		})
	if err != nil || !reflect.DeepEqual(order, []string{"verify", "native", "verify"}) {
		t.Fatalf("unexpected order/error: %v %v", order, err)
	}
	snapshot, err := windowsupdates.Decode(output.Bytes())
	if err != nil || windowsupdates.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		t.Fatal("response is not exactly bound")
	}
}

func TestServeDeniesAbsentOrChangedAuthority(t *testing.T) {
	for _, when := range []int{1, 2} {
		for name, mutate := range map[string]func(*windowsupdates.Request) error{
			"missing":  func(*windowsupdates.Request) error { return windowsupdates.ErrDisabled },
			"disabled": func(r *windowsupdates.Request) error { r.Consent.Enabled = false; return nil },
			"grant":    func(r *windowsupdates.Request) error { r.Consent.GrantID = strings.Repeat("e", 32); return nil },
			"binding": func(r *windowsupdates.Request) error {
				r.SenderBinding = strings.Repeat("e", 64)
				r.Consent.SenderBinding = r.SenderBinding
				return nil
			},
			"capture": func(r *windowsupdates.Request) error { r.CollectedAt = r.CollectedAt.Add(time.Second); return nil },
			"generation": func(r *windowsupdates.Request) error {
				r.GenerationID = "sample_" + strings.Repeat("e", 32)
				return nil
			},
		} {
			t.Run(name+string(rune('0'+when)), func(t *testing.T) {
				raw, _ := encodeRequest(requestFixture())
				checks, reads := 0, 0
				var out bytes.Buffer
				err := Serve(context.Background(), bytes.NewReader(raw), &out,
					func(_ context.Context, req windowsupdates.Request) (windowsupdates.Request, error) {
						checks++
						if checks == when {
							err := mutate(&req)
							return req, err
						}
						return req, nil
					},
					func(_ context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
						reads++
						return snapshotFixture(req), nil
					})
				if err == nil || out.Len() != 0 || checks != when || reads != when-1 {
					t.Fatalf("authority change not terminal: checks=%d reads=%d", checks, reads)
				}
			})
		}
	}
}

func TestServeRevalidatesFailedNativeAndRejectsForeignSnapshot(t *testing.T) {
	for _, failNative := range []bool{true, false} {
		raw, _ := encodeRequest(requestFixture())
		checks := 0
		var out bytes.Buffer
		err := Serve(context.Background(), bytes.NewReader(raw), &out,
			func(_ context.Context, req windowsupdates.Request) (windowsupdates.Request, error) {
				checks++
				return req, nil
			},
			func(_ context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
				if failNative {
					return windowsupdates.Snapshot{}, windowsupdates.ErrUnavailable
				}
				snapshot := snapshotFixture(req)
				snapshot.GenerationID = "sample_" + strings.Repeat("e", 32)
				return snapshot, nil
			})
		if err == nil || checks != 2 || out.Len() != 0 {
			t.Fatal("native failure/foreign snapshot skipped revalidation or emitted output")
		}
	}
}

func TestServeMalformedInputHasNoAuthorityOrNativeRead(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{'x'}, maxRequestBytes+2)} {
		var out bytes.Buffer
		reads := 0
		err := Serve(context.Background(), bytes.NewReader(raw), &out,
			func(_ context.Context, req windowsupdates.Request) (windowsupdates.Request, error) {
				reads++
				return req, nil
			},
			func(_ context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
				reads++
				return snapshotFixture(req), nil
			})
		if err == nil || reads != 0 || out.Len() != 0 {
			t.Fatal("malformed request caused a read or output")
		}
	}
}

func TestBoundedOutputCancelsAndDoesNotRetainOverflow(t *testing.T) {
	canceled := 0
	out := boundedOutput{cancel: func() { canceled++ }}
	if _, err := out.Write(bytes.Repeat([]byte{'a'}, windowsupdates.MaxBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte{'b'}); !errors.Is(err, windowsupdates.ErrBounds) || canceled != 1 || !out.exceeded || out.Len() != windowsupdates.MaxBytes {
		t.Fatal("overflow was not bounded and canceled")
	}
}

// TestWorkerFixture runs only an inert synthetic child. No case opens WUA,
// changes grants, reads a host inventory or touches a real installed receipt.
func TestWorkerFixture(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "worker-fixture:") {
		return
	}
	mode = strings.TrimPrefix(mode, "worker-fixture:")
	if mode == "pipe-holder" {
		// Finite descendant fixture: it retains stdout after its worker parent
		// exits, then closes naturally without touching any native source.
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
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, windowsupdates.MaxBytes+1))
		time.Sleep(time.Hour)
		os.Exit(91)
	}
	if mode == "malformed" {
		_, _ = os.Stdout.Write([]byte("not a snapshot"))
		os.Exit(0)
	}
	if mode == "environment" {
		for _, value := range os.Environ() {
			if runtime.GOOS != "windows" || !strings.HasPrefix(value, "SystemRoot=") {
				os.Exit(92)
			}
		}
	}
	checks := 0
	err := Serve(context.Background(), os.Stdin, os.Stdout,
		func(_ context.Context, req windowsupdates.Request) (windowsupdates.Request, error) {
			checks++
			if mode == "denied" || mode == "revoked" && checks == 2 {
				return windowsupdates.Request{}, windowsupdates.ErrDisabled
			}
			return req, nil
		},
		func(_ context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
			if mode == "denied" {
				os.Exit(99) // distinct evidence if an absent grant reached native.
			}
			snapshot := snapshotFixture(req)
			if mode == "rebound" {
				snapshot.GrantID = strings.Repeat("e", 32)
			}
			return snapshot, nil
		})
	if err != nil {
		if errors.Is(err, windowsupdates.ErrDisabled) {
			os.Exit(31)
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

func assertReaped(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if child == nil || child.Process == nil || child.ProcessState == nil {
		t.Fatal("child was not started and synchronously waited")
	}
	if err := child.Process.Kill(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("child still had a live/unreaped process handle: %v", err)
	}
}

func TestSubprocessBudgetKillsAndReaps(t *testing.T) {
	for _, mode := range []string{"blocked", "never-read"} {
		t.Run(mode, func(t *testing.T) {
			var child *exec.Cmd
			start := time.Now()
			snapshot, err := collect(context.Background(), requestFixture(), 250*time.Millisecond, fixtureFactory(t, mode, &child))
			if err != nil || snapshot.Quality != "unavailable" || snapshot.Reason != windowsupdates.ErrBudget.Error() || windowsupdates.Validate(snapshot) != nil {
				t.Fatalf("budget did not produce finite snapshot: %+v %v", snapshot, err)
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
		snapshot, err := collect(ctx, requestFixture(), 10*time.Second, fixtureFactory(t, "blocked", &child))
		cancel()
		if !errors.Is(err, want) || !reflect.DeepEqual(snapshot, windowsupdates.Snapshot{}) {
			t.Fatalf("caller cancellation not preserved: %v", err)
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
	snapshot, err := collect(context.Background(), requestFixture(), 10*time.Second, fixtureFactory(t, "inherited-pipe", &child))
	// The inert holder has its own fixed 800ms lifetime (plus race-runtime exit
	// delay). Wait for that fixture to finish before leaving the test process.
	defer time.Sleep(2 * time.Second)
	if err != nil || snapshot.Reason != windowsupdates.ErrUnavailable.Error() || snapshot.Quality != "unavailable" {
		t.Fatalf("inherited pipe was not rejected: %+v %v", snapshot, err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("Wait retained the descendant pipe instead of honoring WaitDelay")
	}
	assertReaped(t, child)
	if child.WaitDelay != pipeWaitDelay {
		t.Fatal("pipe wait bound missing")
	}
}

func TestSubprocessResponsesAndEnvironment(t *testing.T) {
	t.Setenv("TRACEBOLT_WORKER_PRIVATE_TEST_SECRET", "must-not-reach-child")
	for _, tc := range []struct{ mode, quality, reason string }{
		{"success", "observed", ""},
		{"environment", "observed", ""},
		{"overflow", "unavailable", windowsupdates.ErrBounds.Error()},
		{"malformed", "unavailable", windowsupdates.ErrMetadata.Error()},
		{"rebound", "unavailable", windowsupdates.ErrUnavailable.Error()},
		{"denied", "unavailable", windowsupdates.ErrUnavailable.Error()},
		{"revoked", "unavailable", windowsupdates.ErrUnavailable.Error()},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var child *exec.Cmd
			snapshot, err := collect(context.Background(), requestFixture(), windowsupdates.CollectionBudget, fixtureFactory(t, tc.mode, &child))
			if err != nil || snapshot.Quality != tc.quality || snapshot.Reason != tc.reason || windowsupdates.Validate(snapshot) != nil {
				t.Fatalf("unexpected response: %+v %v", snapshot, err)
			}
			assertReaped(t, child)
			if (tc.mode == "denied" || tc.mode == "revoked") && child.ProcessState.ExitCode() != 31 {
				t.Fatal("absent grant reached native or revoked grant emitted a response")
			}
			if !bytes.Equal(readRequestFromCommand(t, child), mustEncodeRequest(t, requestFixture())) {
				t.Fatal("worker received unexpected input")
			}
		})
	}
}

func mustEncodeRequest(t *testing.T, req windowsupdates.Request) []byte {
	t.Helper()
	raw, err := encodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readRequestFromCommand(t *testing.T, command *exec.Cmd) []byte {
	t.Helper()
	reader, ok := command.Stdin.(*bytes.Reader)
	if !ok {
		t.Fatal("stdin is not a finite canonical memory reader")
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type countedInput struct {
	reader io.Reader
	read   int
}

func (r *countedInput) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestServeBoundsInputAndOutputWrites(t *testing.T) {
	input := &countedInput{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, maxRequestBytes*4))}
	err := Serve(context.Background(), input, io.Discard, resolveFixture,
		func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error) {
			t.Fatal("oversized request reached native")
			return windowsupdates.Snapshot{}, nil
		})
	if err == nil || input.read != maxRequestBytes+1 {
		t.Fatalf("input exceeded bounded read: %d %v", input.read, err)
	}
	err = Serve(context.Background(), bytes.NewReader(mustEncodeRequest(t, requestFixture())), shortOutput{}, resolveFixture,
		func(_ context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
			return snapshotFixture(req), nil
		})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short output write accepted")
	}
	var output any = &boundedOutput{}
	if _, bypass := output.(io.ReaderFrom); bypass {
		t.Fatal("io.Copy can bypass the bounded Write method")
	}
}

func TestProcessConstructionFailureIsFiniteUnavailable(t *testing.T) {
	snapshot, err := collect(context.Background(), requestFixture(), time.Second,
		func(context.Context) (*exec.Cmd, error) { return nil, errors.New("private process startup details") })
	if err != nil || snapshot.Reason != windowsupdates.ErrUnavailable.Error() || windowsupdates.Validate(snapshot) != nil {
		t.Fatal("process failure leaked raw error or prevented ordinary reporting")
	}
}
