package windowsservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

const maliciousDiagnosticText = "invitation-SECRET\nC:\\private\\identity.key\nmanager-hostname-PRIVATE 198.51.100.99 fingerprint-PRIVATE token-SECRET"

type hostileDiagnosticCause struct{}

func (*hostileDiagnosticCause) Error() string                { panic(maliciousDiagnosticText) }
func (*hostileDiagnosticCause) GoString() string             { panic(maliciousDiagnosticText) }
func (*hostileDiagnosticCause) Format(fmt.State, rune)       { panic(maliciousDiagnosticText) }
func (*hostileDiagnosticCause) MarshalJSON() ([]byte, error) { panic(maliciousDiagnosticText) }
func (*hostileDiagnosticCause) As(any) bool                  { panic(maliciousDiagnosticText) }

type cyclicDiagnosticCause struct{}

func (e *cyclicDiagnosticCause) Error() string { return maliciousDiagnosticText }
func (e *cyclicDiagnosticCause) Unwrap() error { return e }

type hostileUnwrapper struct{}

func (*hostileUnwrapper) Error() string { return maliciousDiagnosticText }
func (*hostileUnwrapper) Unwrap() error { panic(maliciousDiagnosticText) }

type joinWithoutFormatting []error

func (joinWithoutFormatting) Error() string     { panic(maliciousDiagnosticText) }
func (e joinWithoutFormatting) Unwrap() []error { return e }

func assertSafeDiagnosticText(t *testing.T, s string) {
	t.Helper()
	if len(s) > 512 {
		t.Fatalf("diagnostic not bounded: %d bytes", len(s))
	}
	for _, private := range []string{"invitation", "SECRET", "C:\\", "private", "identity.key", "manager-hostname", "198.51.100.99", "fingerprint", "token"} {
		if strings.Contains(s, private) {
			t.Fatalf("diagnostic leaked a private marker (%q)", private)
		}
	}
}

func TestMarkedDiagnosticNeverFormatsCause(t *testing.T) {
	cause := &hostileDiagnosticCause{}
	err := Mark(PhaseSender, ReasonSenderFailed, cause)
	want := DiagnosticStatus{PhaseSender, ReasonSenderFailed, 2109}
	if got := Describe(err); got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("cause identity was lost")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%+q", "%#q", "%x", "%X", "%#x", "%b", "%d", "%o", "%f", "%e", "%g", "%U", "%t", "%c", "%1000000v", "%.1000000v", "%T", "%p"} {
		t.Run(format, func(t *testing.T) {
			assertSafeDiagnosticText(t, fmt.Sprintf(format, err))
			assertSafeDiagnosticText(t, fmt.Sprintf(format, Describe(err)))
		})
	}
	assertSafeDiagnosticText(t, err.Error())
	assertSafeDiagnosticText(t, err.(*diagnosticError).GoString())
	assertSafeDiagnosticText(t, fmt.Sprintf("%#v", struct{ Err error }{err}))
	assertSafeDiagnosticText(t, fmt.Sprintf("%+v", []error{err}))
	assertSafeDiagnosticText(t, fmt.Sprintf("%#v", map[string]error{"error": err}))
	for _, value := range []any{err, Describe(err), struct{ Err error }{err}, []error{err}, map[string]error{"error": err}} {
		encoded, jsonErr := json.Marshal(value)
		if jsonErr != nil {
			t.Fatal(jsonErr)
		}
		assertSafeDiagnosticText(t, string(encoded))
	}
	encoded, jsonErr := json.Marshal(err)
	if jsonErr != nil || string(encoded) != `{"phase":"sender","reason":"sender_failed","serviceSpecificExitCode":2109}` {
		t.Fatalf("unexpected sanitized JSON: %q, %v", encoded, jsonErr)
	}
}

func TestDiagnosticWrappedJoinedAndUnknownErrors(t *testing.T) {
	marked := Mark(PhaseBootstrap, ReasonInvalidConfiguration, errors.New(maliciousDiagnosticText))
	want := DiagnosticStatus{PhaseBootstrap, ReasonInvalidConfiguration, 1601}
	for _, err := range []error{
		marked,
		fmt.Errorf("%s: %w", maliciousDiagnosticText, marked),
		errors.Join(errors.New(maliciousDiagnosticText), marked),
		joinWithoutFormatting{&hostileDiagnosticCause{}, marked},
	} {
		if got := Describe(err); got != want {
			t.Fatalf("wrapped classification changed: %v", got)
		}
		assertSafeDiagnosticText(t, Describe(err).String())
		// Re-mark a foreign wrapper before formatting it: an arbitrary outer
		// fmt.Errorf is outside the sanitizer's control and may contain text.
		d := Describe(err)
		assertSafeDiagnosticText(t, fmt.Sprintf("%#v", Mark(d.Phase, d.Reason, err)))
	}
	unknown := DiagnosticStatus{PhaseUnknown, ReasonUnknown, 1000}
	for _, err := range []error{
		errors.New(maliciousDiagnosticText),
		&hostileDiagnosticCause{},
		&cyclicDiagnosticCause{},
		&hostileUnwrapper{},
		joinWithoutFormatting{errors.New(maliciousDiagnosticText)},
		(*diagnosticError)(nil),
	} {
		if got := Describe(err); got != unknown {
			t.Fatalf("untrusted error did not fail closed: %v", got)
		}
		assertSafeDiagnosticText(t, Describe(err).String())
	}
	deep := marked
	for range 128 {
		deep = fmt.Errorf("%s: %w", maliciousDiagnosticText, deep)
	}
	if got := Describe(deep); got != unknown {
		t.Fatal("unbounded-depth chain was inspected")
	}
	wide := make(joinWithoutFormatting, 10000)
	wide[len(wide)-1] = marked
	if got := Describe(wide); got != unknown {
		t.Fatal("unbounded-width chain was inspected")
	}
}

func TestDiagnosticUnknownLabelsAndTamperedStatusFailClosed(t *testing.T) {
	want := DiagnosticStatus{PhaseUnknown, ReasonUnknown, 1000}
	for _, pair := range []struct {
		phase  Phase
		reason Reason
	}{
		{Phase(maliciousDiagnosticText), ReasonStateRejected},
		{PhaseRetainedState, Reason(maliciousDiagnosticText)},
		{Phase(maliciousDiagnosticText), Reason(maliciousDiagnosticText)},
		{"", ReasonStateRejected},
		{PhaseRetainedState, ""},
		{"", ""},
	} {
		err := Mark(pair.phase, pair.reason, errors.New(maliciousDiagnosticText))
		if got := Describe(err); got != want {
			t.Fatalf("unknown labels escaped the allowlist: %v", got)
		}
		assertSafeDiagnosticText(t, fmt.Sprintf("%#v", err))
		tampered := DiagnosticStatus{pair.phase, pair.reason, 1}
		assertSafeDiagnosticText(t, fmt.Sprintf("%#v", tampered))
		encoded, jsonErr := json.Marshal(tampered)
		if jsonErr != nil {
			t.Fatal(jsonErr)
		}
		assertSafeDiagnosticText(t, string(encoded))
		if string(encoded) != `{"phase":"unknown","reason":"unknown","serviceSpecificExitCode":1000}` {
			t.Fatalf("tampered diagnostic serialized: %q", encoded)
		}
	}
	tampered := DiagnosticStatus{PhaseSender, ReasonSenderFailed, 0}
	encoded, _ := json.Marshal(tampered)
	if !strings.Contains(string(encoded), `"serviceSpecificExitCode":2109`) {
		t.Fatal("caller-provided zero code changed an error into success")
	}
}

func TestDiagnosticCodesAreStableAndUnique(t *testing.T) {
	phases := []struct {
		phase Phase
		id    uint32
	}{
		{PhaseUnknown, 0}, {PhaseSetup, 1}, {PhaseReceipt, 2}, {PhaseRuntimeDispatch, 3},
		{PhaseRuntimeIdentity, 4}, {PhaseRuntimeInstallation, 5}, {PhaseBootstrap, 6},
		{PhaseRetainedState, 7}, {PhasePendingApproval, 8}, {PhaseEnrollment, 9},
		{PhaseHandoff, 10}, {PhaseSender, 11}, {PhaseLifecycle, 12},
	}
	reasons := []struct {
		reason Reason
		id     uint32
	}{
		{ReasonUnknown, 0}, {ReasonInvalidConfiguration, 1}, {ReasonIdentityRejected, 2},
		{ReasonRuntimeReadDenied, 3}, {ReasonStateRejected, 4}, {ReasonApprovalExpired, 5},
		{ReasonEnrollmentTerminal, 6}, {ReasonEnrollmentFailed, 7}, {ReasonHandoffInvalid, 8},
		{ReasonSenderFailed, 9}, {ReasonInputFailed, 10}, {ReasonOperationFailed, 11},
		{ReasonUnsupportedPlatform, 12}, {ReasonInvalidArguments, 13},
		{ReasonDispatcherUnavailable, 14}, {ReasonUnsafePath, 15}, {ReasonStateUnavailable, 16},
		{ReasonInterrupted, 17}, {ReasonResultEncoding, 18}, {ReasonResultWrite, 19},
		{ReasonUnexpectedExit, 20}, {ReasonInputRejected, 21},
	}
	seen := make(map[uint32]string)
	for _, phase := range phases {
		for _, reason := range reasons {
			err := Mark(phase.phase, reason.reason, errors.New("fixture"))
			got := ServiceExitCode(err)
			want := uint32(1000) + 100*phase.id + reason.id
			if got != want || got == 0 || got == 1 {
				t.Fatalf("unstable code for %s/%s: got %d, want %d", phase.phase, reason.reason, got, want)
			}
			if previous := seen[got]; previous != "" {
				t.Fatalf("service code %d was reused: %s", got, previous)
			}
			seen[got] = string(phase.phase) + "/" + string(reason.reason)
			assertSafeDiagnosticText(t, err.Error())
			if Diagnostic(err) != Describe(err) {
				t.Fatal("diagnostic aliases disagree")
			}
		}
	}
}

func TestDiagnosticClassifiesKnownSentinelsWithoutRawText(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want DiagnosticStatus
	}{
		{ErrUnsupported, DiagnosticStatus{PhaseLifecycle, ReasonUnsupportedPlatform, 2212}},
		{ErrUnsafeIdentity, DiagnosticStatus{PhaseRuntimeIdentity, ReasonIdentityRejected, 1402}},
		{ErrRuntimeReadAccess, DiagnosticStatus{PhaseRuntimeInstallation, ReasonRuntimeReadDenied, 1503}},
		{ErrUnsafePath, DiagnosticStatus{PhaseRuntimeInstallation, ReasonUnsafePath, 1515}},
		{ErrMismatch, DiagnosticStatus{PhaseRuntimeInstallation, ReasonInvalidConfiguration, 1501}},
		{ErrNotInstalled, DiagnosticStatus{PhaseRuntimeInstallation, ReasonInvalidConfiguration, 1501}},
		{ErrExisting, DiagnosticStatus{PhaseSetup, ReasonInvalidConfiguration, 1101}},
		{ErrNotStopped, DiagnosticStatus{PhaseLifecycle, ReasonInvalidConfiguration, 2201}},
		{context.Canceled, DiagnosticStatus{PhaseLifecycle, ReasonInterrupted, 2217}},
		{context.DeadlineExceeded, DiagnosticStatus{PhaseLifecycle, ReasonInterrupted, 2217}},
	} {
		err := fmt.Errorf("%s: %w", maliciousDiagnosticText, tc.err)
		if got := Diagnostic(err); got != tc.want {
			t.Fatalf("incorrect sentinel classification: got %v, want %v", got, tc.want)
		}
		assertSafeDiagnosticText(t, Diagnostic(err).String())
	}
}

func TestDiagnosticCancellationPreservationAndSuccess(t *testing.T) {
	if Mark(PhaseSender, ReasonSenderFailed, nil) != nil || ServiceExitCode(nil) != 0 || Describe(nil) != (DiagnosticStatus{}) {
		t.Fatal("nil error no longer represents a successful stop")
	}
	err := Mark(PhasePendingApproval, ReasonInterrupted, fmt.Errorf("%s: %w", maliciousDiagnosticText, context.Canceled))
	if !errors.Is(err, context.Canceled) || ServiceExitCode(err) == 0 {
		t.Fatal("cancellation cause lost or unexpected cancellation reported as success")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = runLifecycle(ctx, func(ctx context.Context, _ func()) error {
		return Mark(PhasePendingApproval, ReasonInterrupted, ctx.Err())
	}, nil, func(status) {})
	if err != nil || ServiceExitCode(err) != 0 {
		t.Fatalf("orderly service cancellation must stay successful: %v", err)
	}
}

func TestDiagnosticJSONAndWriterIgnoreCause(t *testing.T) {
	err := Mark(PhaseRetainedState, ReasonStateRejected, errors.New(maliciousDiagnosticText))
	var out strings.Builder
	if _, writeErr := fmt.Fprintln(&out, err); writeErr != nil {
		t.Fatal(writeErr)
	}
	assertSafeDiagnosticText(t, out.String())
	if _, writeErr := io.WriteString(&out, strconv.Quote(err.Error())); writeErr != nil {
		t.Fatal(writeErr)
	}
	assertSafeDiagnosticText(t, out.String())
	var decoded struct {
		Phase       string `json:"phase"`
		Reason      string `json:"reason"`
		ServiceCode uint32 `json:"serviceSpecificExitCode"`
	}
	raw, jsonErr := json.Marshal(err)
	if jsonErr != nil || json.Unmarshal(raw, &decoded) != nil {
		t.Fatal("safe diagnostic could not be round-tripped")
	}
	if decoded.Phase != "retained_state" || decoded.Reason != "state_rejected" || decoded.ServiceCode != 1704 {
		t.Fatal("safe diagnostic fields changed")
	}
}
