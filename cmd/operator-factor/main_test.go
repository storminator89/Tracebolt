package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	client "localrmm/internal/operatorfactorclient"
	custody "localrmm/internal/operatorfactorcustody"
	"reflect"
	"strings"
	"testing"
)

const testActor = "operator_11111111111111111111111111111111"
const testTarget = "operator_22222222222222222222222222222222"
const credentialCanary = "synthetic-credential-canary-never-print"

type fakeClient struct {
	sessionCleared                             bool
	events                                     *[]string
	checkErr, loginErr, mutationErr, logoutErr error
	admin                                      bool
	rows                                       []client.Account
	logins, enrolls, resets, logouts, closed   int
}

func (f *fakeClient) add(s string)                { *f.events = append(*f.events, s) }
func (f *fakeClient) Check(context.Context) error { f.add("check"); return f.checkErr }
func (f *fakeClient) Login(_ context.Context, u string, p, o []byte) error {
	f.add("login")
	f.logins++
	if u != "admin" || string(p) != credentialCanary {
		return errors.New(credentialCanary)
	}
	return f.loginErr
}
func (f *fakeClient) Enroll(_ context.Context, u string, p, o []byte, r uint64) error {
	f.add("enroll")
	f.enrolls++
	if u != "admin" || string(p) != credentialCanary || string(o) != "12345678" || r != 7 {
		return errors.New(credentialCanary)
	}
	return f.mutationErr
}
func (f *fakeClient) Reset(_ context.Context, target string, r uint64, p, o []byte) error {
	f.add("reset")
	f.resets++
	if target != f.rows[0].ID || r != 7 || string(p) != credentialCanary || string(o) != "87654321" {
		return errors.New(credentialCanary)
	}
	if f.mutationErr == nil && target == testActor {
		f.sessionCleared = true
	}
	return f.mutationErr
}
func (f *fakeClient) Accounts(context.Context) ([]client.Account, error) {
	f.add("accounts")
	return f.rows, nil
}
func (f *fakeClient) Logout(ctx context.Context) error {
	f.add("logout")
	f.logouts++
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("missing bounded cleanup")
	}
	if f.sessionCleared {
		return client.ErrUnauthenticated
	}
	return f.logoutErr
}
func (f *fakeClient) ActorID() string {
	if f.sessionCleared {
		return ""
	}
	return testActor
}
func (f *fakeClient) CanManageAccounts() bool { return f.admin }
func (f *fakeClient) Close()                  { f.add("close"); f.closed++ }

type fakePlan struct {
	events *[]string
	stages int
	result custody.Result
	err    error
}

func (f *fakePlan) ClientConfig() client.Config {
	return client.Config{Origin: "https://manager.invalid"}
}
func (f *fakePlan) Stage(_ context.Context, a client.Account) (custody.Result, error) {
	*f.events = append(*f.events, "stage")
	f.stages++
	if a.ID != testTarget || a.Revision != 7 {
		return custody.Result{}, custody.ErrTarget
	}
	return f.result, f.err
}
func fixture(t *testing.T) (dependencies, *fakeClient, *fakePlan, *[][]byte) {
	t.Helper()
	events := []string{}
	api := &fakeClient{events: &events, admin: true, rows: []client.Account{{ID: testTarget, Revision: 7, FactorState: "active", Capabilities: []string{"read"}}}}
	plan := &fakePlan{events: &events, result: custody.Result{ProposalCreated: true, HandoffCreated: true}}
	inputs := [][]byte{}
	deps := dependencies{supported: true, plan: func(custody.Options) (custodyPlan, error) { events = append(events, "plan"); return plan, nil }, certificate: func(string) ([]byte, error) {
		events = append(events, "certificate")
		return []byte("synthetic public fixture"), nil
	}, newClient: func(client.Config) (apiClient, error) { events = append(events, "new"); return api, nil }, prompt: func(_ context.Context, kind string) ([]byte, error) {
		events = append(events, "prompt:"+kind)
		var value string
		switch kind {
		case "username":
			value = "admin"
		case "password", "fresh_password":
			value = credentialCanary
		case "login_otp", "enrollment_otp":
			value = "12345678"
		case "fresh_otp":
			value = "87654321"
		default:
			t.Fatal("unknown prompt kind")
		}
		b := []byte(value)
		inputs = append(inputs, b)
		return b, nil
	}}
	return deps, api, plan, &inputs
}
func commandArgs(command string) []string {
	if command == "prepare" {
		return []string{"prepare", "--lan-config", "/private/lan.json", "--runtime-uid", "1000", "--actor-id", testTarget, "--expected-revision", "7", "--handoff-file", "/private/handoff.json", "--acknowledge-factor-custody"}
	}
	args := []string{command, "--operator-origin", "https://manager.invalid", "--server-certificate-file", "/private/cert.pem"}
	if command != "status" {
		args = append(args, "--expected-revision", "7")
	}
	if command == "reset" {
		args = append(args, "--actor-id", testTarget, "--acknowledge-factor-reset")
	}
	if command == "enroll" {
		args = append(args, "--acknowledge-factor-enrollment")
	}
	return args
}
func runFixture(t *testing.T, args []string, d dependencies) (int, report) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), args, &out, d)
	if strings.Contains(out.String(), credentialCanary) || strings.Contains(out.String(), "12345678") || strings.Contains(out.String(), "87654321") || strings.Contains(out.String(), "/private/") {
		t.Fatal("diagnostic leaked supplied private material")
	}
	var r report
	if json.Unmarshal(out.Bytes(), &r) != nil {
		t.Fatal("invalid fixed JSON report")
	}
	return code, r
}
func TestArgumentAndHelpGatesPrecedeIO(t *testing.T) {
	for _, args := range [][]string{nil, {"--password", credentialCanary}, {"reset", "--password", credentialCanary}, {"reset"}, {"prepare"}, append(commandArgs("enroll")[:len(commandArgs("enroll"))-1], "--unexpected="+credentialCanary)} {
		code, r := runFixture(t, args, dependencies{})
		if code == 0 || r.Code != "arguments" {
			t.Fatal("bad args accepted")
		}
	}
	for _, args := range [][]string{{"--help"}, {"prepare", "--help"}, {"enroll", "--help"}, {"reset", "--help"}, {"status", "--help"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out, dependencies{}) != 0 || !strings.Contains(out.String(), "controlling terminal") || strings.Contains(out.String(), credentialCanary) {
			t.Fatal("help did I/O or leaked")
		}
	}
	d, api, plan, _ := fixture(t)
	d.supported = false
	_, r := runFixture(t, commandArgs("prepare"), d)
	if r.Code != "unsupported" || len(*api.events) != 0 || plan.stages != 0 {
		t.Fatal("unsupported platform performed I/O")
	}
}
func TestCheckedProfileBeforeCredentialPromptOrStage(t *testing.T) {
	d, api, plan, _ := fixture(t)
	api.checkErr = client.ErrUnsupported
	_, r := runFixture(t, commandArgs("prepare"), d)
	if r.Code != "unsupported" || plan.stages != 0 || api.logins != 0 || strings.Contains(strings.Join(*api.events, ","), "prompt:") {
		t.Fatal("unverified endpoint prompted or staged")
	}
}
func TestResetFreshRequesterProofExplicitCleanupAndNoRetry(t *testing.T) {
	for _, mode := range []string{"success", "uncertain", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			d, api, _, inputs := fixture(t)
			if mode == "uncertain" {
				api.mutationErr = client.ErrUncertain
			}
			if mode == "cleanup" {
				api.logoutErr = client.ErrUncertain
			}
			code, r := runFixture(t, commandArgs("reset"), d)
			if api.resets != 1 || api.logins != 1 || api.logouts != 1 || api.closed != 1 {
				t.Fatal("missing explicit cleanup or automatic retry")
			}
			want := []string{"certificate", "new", "check", "prompt:username", "prompt:password", "prompt:login_otp", "login", "accounts", "prompt:fresh_password", "prompt:fresh_otp", "reset", "logout", "close"}
			if !reflect.DeepEqual(*api.events, want) {
				t.Fatal("fresh proof ordering changed")
			}
			if mode == "success" && (code != 0 || !r.Confirmed || !r.OperationApplied || r.CleanupConfirmed == nil || !*r.CleanupConfirmed) {
				t.Fatal("missing confirmed success")
			}
			if mode == "uncertain" && (code == 0 || r.Confirmed || r.OperationApplied || !r.OperationUncertain || r.Code != "uncertain") {
				t.Fatal("uncertain mutation claimed success")
			}
			if mode == "cleanup" && (code == 0 || !r.Confirmed || !r.OperationApplied || r.Code != "cleanup_unconfirmed" || r.CleanupConfirmed == nil || *r.CleanupConfirmed) {
				t.Fatal("cleanup erased confirmed mutation outcome")
			}
			for _, b := range *inputs {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("credential buffer retained")
				}
			}
		})
	}
}
func TestEnrollmentNeverLogsInOrIssuesImplicitCleanup(t *testing.T) {
	d, api, _, _ := fixture(t)
	code, r := runFixture(t, commandArgs("enroll"), d)
	if code != 0 || !r.OperationApplied || api.enrolls != 1 || api.logins != 0 || api.logouts != 0 || r.CleanupConfirmed != nil {
		t.Fatal("enrollment incorrectly used session workflow")
	}
}
func TestPrepareReviewGatesAndPartialStateTruth(t *testing.T) {
	for _, mode := range []string{"success", "forbidden", "conflict", "disabled", "uncertain_target", "active", "partial", "uncertain_without_flags"} {
		t.Run(mode, func(t *testing.T) {
			d, api, plan, _ := fixture(t)
			api.rows[0].FactorState = "enrollment_required"
			switch mode {
			case "forbidden":
				api.admin = false
			case "conflict":
				api.rows[0].Revision++
			case "disabled":
				api.rows[0].Disabled = true
			case "uncertain_target":
				api.rows[0].Uncertain = true
			case "active":
				api.rows[0].FactorState = "active"
			case "partial":
				plan.result = custody.Result{HandoffCreated: true}
				plan.err = custody.ErrUncertain
			case "uncertain_without_flags":
				plan.result = custody.Result{}
				plan.err = custody.ErrUncertain
			}
			code, r := runFixture(t, commandArgs("prepare"), d)
			if api.logouts != 1 {
				t.Fatal("review failure skipped cleanup")
			}
			if mode == "success" {
				if code != 0 || plan.stages != 1 || !r.ProposalCreated || !r.HandoffCreated || !r.OperationApplied {
					t.Fatal("missing staged result")
				}
			} else if mode == "partial" {
				if code == 0 || plan.stages != 1 || !r.HandoffCreated || r.ProposalCreated || !r.OperationUncertain || r.Confirmed {
					t.Fatal("partial custody state hidden")
				}
			} else if mode == "uncertain_without_flags" {
				if code == 0 || plan.stages != 1 || !r.OperationUncertain || r.OperationApplied || r.Confirmed || r.Code != "uncertain" {
					t.Fatal("uncertain custody without known effects misreported as rejection")
				}
			} else if code == 0 || plan.stages != 0 {
				t.Fatal("stage bypassed exact review")
			}
		})
	}
}
func TestSameLoginOTPNotReusedAndFailedLoginCleansUp(t *testing.T) {
	d, api, _, _ := fixture(t)
	old := d.prompt
	d.prompt = func(ctx context.Context, kind string) ([]byte, error) {
		if kind == "fresh_otp" {
			return []byte("12345678"), nil
		}
		return old(ctx, kind)
	}
	_, r := runFixture(t, commandArgs("reset"), d)
	if r.Code != "fresh_code_required" || api.resets != 0 || api.logouts != 1 {
		t.Fatal("same OTP reused")
	}
	d, api, _, _ = fixture(t)
	api.loginErr = client.ErrUncertain
	_, r = runFixture(t, commandArgs("reset"), d)
	if !r.OperationUncertain || api.logouts != 1 || api.resets != 0 || strings.Contains(strings.Join(*api.events, ","), "accounts") {
		t.Fatal("uncertain login continued or skipped cleanup")
	}
}
func TestStatusIsAdminOnlyAndRedacted(t *testing.T) {
	d, api, _, _ := fixture(t)
	code, r := runFixture(t, commandArgs("status"), d)
	if code != 0 || len(r.Accounts) != 1 || r.Accounts[0].ID != testTarget || r.OperationApplied || api.logouts != 1 {
		t.Fatal("status contract")
	}
	d, api, _, _ = fixture(t)
	api.admin = false
	_, r = runFixture(t, commandArgs("status"), d)
	if r.Code != "forbidden" || len(r.Accounts) != 0 {
		t.Fatal("status silently expanded read scope")
	}
}
func TestHiddenFieldBounds(t *testing.T) {
	for _, tc := range []struct {
		kind, value string
		valid       bool
	}{{"username", "admin-1", true}, {"username", "Admin", false}, {"username", "-admin", false}, {"password", credentialCanary, true}, {"password", "short", false}, {"password", credentialCanary + "\n", false}, {"login_otp", "", true}, {"enrollment_otp", "", false}, {"fresh_otp", "00123456", true}, {"fresh_otp", "12345678\n", false}, {"fresh_otp", "１２３４５６７８", false}} {
		if validInput(tc.kind, []byte(tc.value)) != tc.valid {
			t.Fatal("hidden input validation mismatch")
		}
	}
}

func TestMissingAcknowledgementAndDuplicateReviewFlagsNeverTouchDependencies(t *testing.T) {
	for _, command := range []string{"prepare", "enroll", "reset"} {
		args := commandArgs(command)
		args = args[:len(args)-1]
		code, r := runFixture(t, args, dependencies{})
		if code == 0 || r.Code != "arguments" {
			t.Fatal("missing explicit acknowledgement accepted")
		}
	}
	for _, args := range [][]string{append(commandArgs("reset"), "--expected-revision", "8"), append(commandArgs("prepare"), "--actor-id", testActor), append(commandArgs("status"), "--username", credentialCanary), append(commandArgs("enroll"), "--otp", "12345678")} {
		code, r := runFixture(t, args, dependencies{})
		if code == 0 || r.Code != "arguments" {
			t.Fatal("ambiguous or credential arguments accepted")
		}
	}
}
func TestConcurrentCommandsKeepSessionAndCredentialBuffersSeparate(t *testing.T) {
	for _, command := range []string{"reset", "enroll", "prepare", "status"} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			d, api, _, buffers := fixture(t)
			if command == "prepare" {
				api.rows[0].FactorState = ""
			}
			code, _ := runFixture(t, commandArgs(command), d)
			if code != 0 || api.closed != 1 {
				t.Fatal("isolated command failed")
			}
			for _, b := range *buffers {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("isolated command retained credential")
				}
			}
		})
	}
}
func TestCanceledPromptRestoresCleanupWithoutRetry(t *testing.T) {
	d, api, _, _ := fixture(t)
	original := d.prompt
	d.prompt = func(ctx context.Context, kind string) ([]byte, error) {
		if kind == "fresh_otp" {
			return []byte(credentialCanary), context.Canceled
		}
		return original(ctx, kind)
	}
	code, r := runFixture(t, commandArgs("reset"), d)
	if code == 0 || r.Code != "terminal_input" || api.resets != 0 || api.logouts != 1 {
		t.Fatal("canceled proof dispatched or lost cleanup")
	}
}

func TestConfirmedSelfResetIsNotFalseCleanupFailure(t *testing.T) {
	d, api, _, _ := fixture(t)
	api.rows[0].ID = testActor
	args := commandArgs("reset")
	for i, arg := range args {
		if arg == "--actor-id" {
			args[i+1] = testActor
		}
	}
	code, result := runFixture(t, args, d)
	if code != 0 || !result.Confirmed || !result.OperationApplied || result.CleanupConfirmed == nil || !*result.CleanupConfirmed || api.resets != 1 || api.logouts != 1 || !api.sessionCleared {
		t.Fatal("confirmed self reset reported uncertain cleanup")
	}
	// Unauthenticated cleanup alone is not proof that a different target's reset
	// ended the requester's session, and must not be treated as confirmed.
	d, api, _, _ = fixture(t)
	api.logoutErr = client.ErrUnauthenticated
	code, result = runFixture(t, commandArgs("reset"), d)
	if code == 0 || result.Code != "cleanup_unconfirmed" || !result.OperationApplied || result.CleanupConfirmed == nil || *result.CleanupConfirmed {
		t.Fatal("unrelated logout rejection was treated as confirmed cleanup")
	}
}
