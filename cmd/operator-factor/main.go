// operator-factor is an explicit, foreground-only factor custody/API client.
// Credentials are read only from the controlling terminal, never flags or stdin.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	client "localrmm/internal/operatorfactorclient"
	custody "localrmm/internal/operatorfactorcustody"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var errInput = errors.New("terminal input rejected")

type apiClient interface {
	Check(context.Context) error
	Login(context.Context, string, []byte, []byte) error
	Enroll(context.Context, string, []byte, []byte, uint64) error
	Reset(context.Context, string, uint64, []byte, []byte) error
	Accounts(context.Context) ([]client.Account, error)
	Logout(context.Context) error
	ActorID() string
	CanManageAccounts() bool
	Close()
}
type custodyPlan interface {
	ClientConfig() client.Config
	Stage(context.Context, client.Account) (custody.Result, error)
}
type dependencies struct {
	supported   bool
	plan        func(custody.Options) (custodyPlan, error)
	newClient   func(client.Config) (apiClient, error)
	certificate func(string) ([]byte, error)
	prompt      func(context.Context, string) ([]byte, error)
}
type options struct {
	command, origin, certificate, lanConfig, actor, handoff string
	revision                                                uint64
	uid                                                     int
	ack, replace                                            bool
}
type accountRow struct {
	ID               string   `json:"id"`
	Revision         uint64   `json:"revision"`
	Disabled         bool     `json:"disabled"`
	Uncertain        bool     `json:"uncertain"`
	FactorState      string   `json:"factorState"`
	FactorGeneration uint64   `json:"factorGeneration"`
	Capabilities     []string `json:"capabilities"`
}
type report struct {
	Version            string       `json:"version"`
	Code               string       `json:"code"`
	Confirmed          bool         `json:"confirmed"`
	OperationApplied   bool         `json:"operationApplied"`
	OperationUncertain bool         `json:"operationUncertain"`
	CleanupConfirmed   *bool        `json:"cleanupConfirmed,omitempty"`
	ProposalCreated    bool         `json:"proposalCreated"`
	HandoffCreated     bool         `json:"handoffCreated"`
	Archived           bool         `json:"archived"`
	Accounts           []accountRow `json:"accounts,omitempty"`
}

func fixedCode(code string) string {
	switch code {
	case "staged":
		return "ok"
	case "custody_uncertain":
		return "uncertain"
	case "unsupported_platform":
		return "unsupported"
	case "target_review":
		return "conflict"
	case "existing_state", "pinned_input_changed", "canceled":
		return code
	case "ok", "configuration", "unsupported", "unauthenticated", "forbidden", "conflict", "rejected", "uncertain", "unavailable":
		return code
	}
	return "rejected"
}
func emit(out io.Writer, r report) int {
	r.Version = "tracebolt.operator-factor.v1"
	if json.NewEncoder(out).Encode(r) != nil {
		return 1
	}
	if r.Confirmed && r.Code == "ok" {
		return 0
	}
	return 1
}
func help(out io.Writer) int {
	_, err := fmt.Fprintln(out, `Usage: operator-factor prepare --lan-config ABS --runtime-uid UID --actor-id ID --expected-revision N --handoff-file ABS --acknowledge-factor-custody [--replace-stale-proposal]
       operator-factor enroll --operator-origin HTTPS --server-certificate-file ABS --expected-revision N --acknowledge-factor-enrollment
       operator-factor reset --operator-origin HTTPS --server-certificate-file ABS --actor-id ID --expected-revision N --acknowledge-factor-reset
       operator-factor status --operator-origin HTTPS --server-certificate-file ABS
Linux foreground controlling terminal only. Passwords, usernames, OTPs and secrets are never accepted in arguments, environment variables or redirected stdin. All credential prompts are hidden. Server certificate is public leaf material, not a private key. Prepare requires a current named account administrator and explicit approved private custody. Enrollment consumes its OTP; wait for a fresh code before login. Reset requires fresh requester password and a new unused OTP after login. No automatic retry, recovery, journal edit, manager stop or privilege change. A failed response can mean an uncertain operation: preserve state and review before doing anything else. Cleanup confirmation is separate from operation confirmation. Help performs no network or custody action.`)
	if err != nil {
		return 1
	}
	return 0
}
func parse(args []string) (options, error) {
	var o options
	if len(args) == 0 {
		return o, errInput
	}
	o.command = args[0]
	f := flag.NewFlagSet("operator-factor", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	revision, uid := "", ""
	switch o.command {
	case "prepare":
		f.StringVar(&o.lanConfig, "lan-config", "", "")
		f.StringVar(&uid, "runtime-uid", "", "")
		f.StringVar(&o.actor, "actor-id", "", "")
		f.StringVar(&revision, "expected-revision", "", "")
		f.StringVar(&o.handoff, "handoff-file", "", "")
		f.BoolVar(&o.ack, "acknowledge-factor-custody", false, "")
		f.BoolVar(&o.replace, "replace-stale-proposal", false, "")
	case "enroll", "reset", "status":
		f.StringVar(&o.origin, "operator-origin", "", "")
		f.StringVar(&o.certificate, "server-certificate-file", "", "")
		if o.command != "status" {
			f.StringVar(&revision, "expected-revision", "", "")
			f.BoolVar(&o.ack, "acknowledge-factor-"+map[string]string{"enroll": "enrollment", "reset": "reset"}[o.command], false, "")
		}
		if o.command == "reset" {
			f.StringVar(&o.actor, "actor-id", "", "")
		}
	default:
		return o, errInput
	}
	// Repeated authority/review flags are ambiguous, even if their final value
	// would otherwise parse. Never echo rejected argument values.
	seen := make(map[string]bool)
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[name] {
				return o, errInput
			}
			seen[name] = true
		}
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return o, errInput
	}
	if o.command != "status" {
		var e error
		o.revision, e = strconv.ParseUint(revision, 10, 64)
		if e != nil || o.revision == 0 || strconv.FormatUint(o.revision, 10) != revision || !o.ack {
			return o, errInput
		}
	}
	if o.command == "prepare" {
		n, e := strconv.Atoi(uid)
		if e != nil || n <= 0 || strconv.Itoa(n) != uid || o.lanConfig == "" || o.handoff == "" {
			return o, errInput
		}
		o.uid = n
	} else if o.origin == "" || o.certificate == "" {
		return o, errInput
	}
	if (o.command == "prepare" || o.command == "reset") && !enrollmentcrypto.ValidID(o.actor, "operator_") {
		return o, errInput
	}
	return o, nil
}
func validInput(kind string, b []byte) bool {
	switch kind {
	case "username":
		if len(b) < 1 || len(b) > 64 {
			return false
		}
		for i, c := range b {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-' || c == '.') {
				continue
			}
			return false
		}
		return true
	case "password", "fresh_password":
		if len(b) < 12 || len(b) > 1024 || !utf8.Valid(b) {
			return false
		}
		for _, c := range string(b) {
			if unicode.IsControl(c) || c == utf8.RuneError {
				return false
			}
		}
		return true
	case "login_otp":
		if len(b) == 0 {
			return true
		}
		fallthrough
	case "enrollment_otp", "fresh_otp":
		if len(b) != 8 {
			return false
		}
		for _, c := range b {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}
func readInput(ctx context.Context, d dependencies, kind string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errInput
	}
	b, e := d.prompt(ctx, kind)
	if e != nil || !validInput(kind, b) {
		clear(b)
		return nil, errInput
	}
	return b, nil
}
func run(ctx context.Context, args []string, out io.Writer, d dependencies) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") || len(args) == 2 && (args[1] == "--help" || args[1] == "-h") && (args[0] == "prepare" || args[0] == "enroll" || args[0] == "reset" || args[0] == "status") {
		return help(out)
	}
	o, e := parse(args)
	if e != nil {
		return emit(out, report{Code: "arguments"})
	}
	if !d.supported {
		return emit(out, report{Code: "unsupported"})
	}
	r := execute(ctx, o, d)
	return emit(out, r)
}
func execute(ctx context.Context, o options, d dependencies) (r report) {
	r.Code = "rejected"
	var cfg client.Config
	var plan custodyPlan
	var err error
	if o.command == "prepare" {
		plan, err = d.plan(custody.Options{LanConfig: o.lanConfig, ActorID: o.actor, HandoffFile: o.handoff, RuntimeUID: o.uid, ExpectedRevision: o.revision, Acknowledge: o.ack, ReplaceStale: o.replace})
		if err != nil {
			r.Code = fixedCode(custody.Code(err))
			return
		}
		cfg = plan.ClientConfig()
	} else {
		cfg.Origin = o.origin
		cfg.ServerCertificate, err = d.certificate(o.certificate)
		if err != nil {
			r.Code = "configuration"
			return
		}
	}
	api, err := d.newClient(cfg)
	if err != nil {
		r.Code = fixedCode(client.Code(err))
		return
	}
	defer api.Close()
	if err = api.Check(ctx); err != nil {
		r.Code = fixedCode(client.Code(err))
		return
	}
	// Only a checked live TLS endpoint may trigger a credential prompt.
	username, err := readInput(ctx, d, "username")
	if err != nil {
		r.Code = "terminal_input"
		return
	}
	defer clear(username)
	password, err := readInput(ctx, d, "password")
	if err != nil {
		r.Code = "terminal_input"
		return
	}
	defer clear(password)
	otpKind := "login_otp"
	if o.command == "enroll" {
		otpKind = "enrollment_otp"
	}
	otp, err := readInput(ctx, d, otpKind)
	if err != nil {
		r.Code = "terminal_input"
		return
	}
	defer clear(otp)
	if o.command == "enroll" {
		err = api.Enroll(ctx, string(username), password, otp, o.revision)
		clear(password)
		clear(otp)
		r.Code = fixedCode(client.Code(err))
		r.Confirmed = err == nil
		r.OperationApplied = err == nil
		r.OperationUncertain = r.Code == "uncertain"
		return
	}
	selfResetConfirmed := false
	previousOTP := sha256.Sum256(otp)
	hadOTP := len(otp) != 0
	// Even a lost login response can have minted a server session. Explicitly
	// attempt cleanup with a separate bounded context, never silently in Close.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		logoutErr := api.Logout(cleanup)
		ok := logoutErr == nil || selfResetConfirmed && errors.Is(logoutErr, client.ErrUnauthenticated)
		r.CleanupConfirmed = &ok
		if !ok {
			r.Code = "cleanup_unconfirmed"
		}
	}()
	err = api.Login(ctx, string(username), password, otp)
	clear(password)
	clear(otp)
	if err != nil {
		r.Code = fixedCode(client.Code(err))
		r.OperationUncertain = r.Code == "uncertain"
		return
	}
	if !enrollmentcrypto.ValidID(api.ActorID(), "operator_") || !api.CanManageAccounts() {
		r.Code = "forbidden"
		return
	}
	accounts, err := api.Accounts(ctx)
	if err != nil {
		r.Code = fixedCode(client.Code(err))
		return
	}
	if len(accounts) > 32 {
		r.Code = "rejected"
		return
	}
	if o.command == "status" {
		for _, a := range accounts {
			r.Accounts = append(r.Accounts, accountRow{a.ID, a.Revision, a.Disabled, a.Uncertain, a.FactorState, a.FactorGeneration, append([]string(nil), a.Capabilities...)})
		}
		r.Code = "ok"
		r.Confirmed = true
		return
	}
	var target client.Account
	found := false
	for _, a := range accounts {
		if a.ID == o.actor {
			if found {
				r.Code = "rejected"
				return
			}
			found = true
			target = a
		}
	}
	if !found || target.Revision != o.revision {
		r.Code = "conflict"
		return
	}
	if target.Disabled || target.Uncertain {
		r.Code = "rejected"
		return
	}
	if o.command == "prepare" {
		if target.FactorState != "" && target.FactorState != "enrollment_required" {
			r.Code = "rejected"
			return
		}
		result, e := plan.Stage(ctx, target)
		r.ProposalCreated = result.ProposalCreated
		r.HandoffCreated = result.HandoffCreated
		r.Archived = result.Archived
		r.OperationApplied = result.ProposalCreated || result.HandoffCreated || result.Archived
		r.Confirmed = e == nil
		r.Code = fixedCode(custody.Code(e))
		r.OperationUncertain = errors.Is(e, custody.ErrUncertain) || e != nil && r.OperationApplied || r.Code == "uncertain"
		return
	}
	if target.FactorState != "active" {
		r.Code = "rejected"
		return
	}
	freshPassword, err := readInput(ctx, d, "fresh_password")
	if err != nil {
		r.Code = "terminal_input"
		return
	}
	defer clear(freshPassword)
	freshOTP, err := readInput(ctx, d, "fresh_otp")
	if err != nil {
		r.Code = "terminal_input"
		return
	}
	defer clear(freshOTP)
	if hadOTP && sha256.Sum256(freshOTP) == previousOTP {
		r.Code = "fresh_code_required"
		return
	}
	selfTarget := target.ID == api.ActorID()
	err = api.Reset(ctx, target.ID, target.Revision, freshPassword, freshOTP)
	// The client validates a successful self-reset response and its cookie clear.
	// Only that specific confirmed revocation can satisfy otherwise missing cleanup.
	selfResetConfirmed = err == nil && selfTarget
	clear(freshPassword)
	clear(freshOTP)
	r.Code = fixedCode(client.Code(err))
	r.Confirmed = err == nil
	r.OperationApplied = err == nil
	r.OperationUncertain = r.Code == "uncertain"
	return
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	exit := run(ctx, os.Args[1:], os.Stdout, dependencies{supported: platformSupported, plan: func(o custody.Options) (custodyPlan, error) { return custody.PlanFor(o) }, newClient: func(c client.Config) (apiClient, error) { return client.New(c) }, certificate: func(path string) ([]byte, error) { return readPublicCertificate(path) }, prompt: readTerminal})
	os.Exit(exit)
}

// Accept a public certificate or public-only PEM chain, pinning its first leaf.
// Private-key blocks and trailing data are never accepted as certificate input.
func readPublicCertificate(path string) ([]byte, error) {
	raw, err := lanconfig.ReadProtected(path, false, 65536)
	if err != nil {
		return nil, client.ErrConfiguration
	}
	defer clear(raw)
	if cert, err := x509.ParseCertificate(raw); err == nil {
		return append([]byte(nil), cert.Raw...), nil
	}
	rest := bytes.TrimSpace(raw)
	var leaf []byte
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, client.ErrConfiguration
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, client.ErrConfiguration
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, client.ErrConfiguration
		}
		if leaf == nil {
			leaf = append([]byte(nil), cert.Raw...)
		}
		rest = bytes.TrimSpace(remaining)
	}
	if leaf == nil {
		return nil, client.ErrConfiguration
	}
	return leaf, nil
}
