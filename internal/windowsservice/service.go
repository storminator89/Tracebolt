// Package windowsservice is a source candidate for one fixed Windows service.
// Read-only planning and the SCM runtime are separate from explicit apply calls.
// No function grants filesystem access, enrolls, creates credentials, or deletes
// identity state. Native installation remains a separately authorized VM gate.
package windowsservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

const (
	Name              = "TraceboltWindowsAgent"
	Account           = `NT AUTHORITY\LocalService`
	ServiceAccount    = `NT SERVICE\TraceboltWindowsAgent`
	LocalServiceSID   = "S-1-5-19"
	ExecutableName    = "tracebolt-windows-service.exe"
	RequiredPrivilege = "SeChangeNotifyPrivilege"
)

var (
	ErrUnsupported       = errors.New("Windows SCM service candidate requires Windows")
	ErrNotInstalled      = errors.New("fixed Windows service is not installed")
	ErrExisting          = errors.New("existing service is never adopted or overwritten")
	ErrMismatch          = errors.New("Windows service ownership or configuration mismatch")
	ErrUnsafePath        = errors.New("installed executable or parent path is not trusted")
	ErrRuntimeReadAccess = errors.New("installed executable or parent path lacks the required LocalService read and execute grant")
	ErrUnsafeIdentity    = errors.New("Windows service token does not match the limited runtime identity")
	ErrNotStopped        = errors.New("service must be stopped before uninstall; private state is retained")
)

// Layout is resolved from machine KnownFolder APIs, never the process environment.
// Roots must already be provisioned by a separately authorized administrator.
type Layout struct {
	ProgramFiles   string `json:"programFiles"`
	ProgramData    string `json:"programData"`
	Executable     string `json:"executable"`
	StateRoot      string `json:"stateRoot"`
	EnrollmentRoot string `json:"enrollmentRoot"`
	SenderRoot     string `json:"senderRoot"`
}

func layoutFromRoots(programFiles, programData string) (Layout, error) {
	for _, p := range []string{programFiles, programData} {
		if len(p) < 4 || p[1] != ':' || p[2] != '\\' || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || strings.ContainsAny(p, "/\x00\r\n\"") || strings.HasSuffix(p, `\`) {
			return Layout{}, ErrUnsafePath
		}
		for _, component := range strings.Split(p[3:], `\`) {
			if component == "" || component == "." || component == ".." || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") || strings.Contains(component, ":") {
				return Layout{}, ErrUnsafePath
			}
		}
	}
	root := programData + `\Tracebolt\windows-agent`
	return Layout{programFiles, programData, programFiles + `\Tracebolt\` + ExecutableName, root, root + `\enrollment`, root + `\enrollment\telemetry`}, nil
}

// Configuration contains the complete supported SCM configuration. Callers cannot
// supply alternative names, accounts, arguments, privilege lists or commands.
type Configuration struct {
	Name               string   `json:"name"`
	DisplayName        string   `json:"displayName"`
	BinaryPath         string   `json:"binaryPath"`
	Account            string   `json:"account"`
	ServiceType        uint32   `json:"serviceType"`
	StartType          uint32   `json:"startType"`
	ErrorControl       uint32   `json:"errorControl"`
	SIDType            uint32   `json:"sidType"`
	RequiredPrivileges []string `json:"requiredPrivileges"`
	Dependencies       []string `json:"dependencies"`
	LoadOrderGroup     string   `json:"loadOrderGroup"`
	DelayedAutoStart   bool     `json:"delayedAutoStart"`
	FailureActions     bool     `json:"failureActions"`
	Triggers           bool     `json:"triggers"`
	Description        string   `json:"description"`
}

const descriptionPrefix = "Tracebolt Windows agent candidate; installation="

func configuration(l Layout, installationID, executableSHA256 string) Configuration {
	return Configuration{Name: Name, DisplayName: "Tracebolt Windows Agent", BinaryPath: `"` + l.Executable + `" "--run-service"`, Account: Account, ServiceType: 16, StartType: 2, ErrorControl: 1, SIDType: 1, RequiredPrivileges: []string{RequiredPrivilege}, Dependencies: []string{}, Description: descriptionPrefix + installationID + "; executable-sha256=" + executableSHA256}
}

type State uint32

const (
	Stopped      State = 1
	StartPending State = 2
	StopPending  State = 3
	Running      State = 4
)

type Snapshot struct {
	Exists                  bool          `json:"exists"`
	Configuration           Configuration `json:"configuration"`
	State                   State         `json:"state"`
	ServiceSID              string        `json:"serviceSID,omitempty"`
	ProcessID               uint32        `json:"processID,omitempty"`
	Win32ExitCode           uint32        `json:"win32ExitCode,omitempty"`
	ServiceSpecificExitCode uint32        `json:"serviceSpecificExitCode,omitempty"`
}

type InstallPlan struct {
	Layout           Layout        `json:"layout"`
	Configuration    Configuration `json:"configuration"`
	ExecutableSHA256 string        `json:"executableSHA256"`
	Existing         Snapshot      `json:"existing"`
	InstallationID   string        `json:"installationID"`
}

// Receipt is an ownership record, not an authorization token. The coordinator
// must durably write an intent before ApplyInstall and persist this receipt in
// protected installer state. A missing or incomplete receipt is never recovered
// by adopting a service. Keep incomplete receipts for manual diagnosis.
type Receipt struct {
	Version             int    `json:"version"`
	InstallationID      string `json:"installationID"`
	Layout              Layout `json:"layout"`
	ConfigurationSHA256 string `json:"configurationSHA256"`
	ExecutableSHA256    string `json:"executableSHA256"`
	ServiceSID          string `json:"serviceSID"`
	Complete            bool   `json:"complete"`
}

type ApplyResult struct {
	Snapshot Snapshot `json:"snapshot"`
	// Requested does not assert the asynchronous transition has completed.
	Requested     bool `json:"requested"`
	DeletePending bool `json:"deletePending,omitempty"`
	StateRetained bool `json:"stateRetained"`
}

type access uint8

const (
	readAccess access = iota
	startAccess
	stopAccess
	deleteAccess
)

type service interface {
	Inspect() (Snapshot, error)
	Start() error
	Stop() error
	Delete() error
	Close() error
}
type backend interface {
	Layout() (Layout, error)
	VerifyExecutable(Layout) (string, error)
	Open(access) (service, error)
	Create(Configuration) (service, error)
	LookupSID() (string, error)
}

// Plan reads native state and hashes an already installed, protected executable.
// It makes no filesystem or SCM change. It is not approval to apply this plan.
func Plan(ctx context.Context) (InstallPlan, error) { return plan(ctx, nativeBackend()) }
func Inspect(ctx context.Context) (Snapshot, error) { return inspect(ctx, nativeBackend()) }

// InspectOwned proves the protected receipt's exact SCM binding and trusted
// executable bytes using read-only access. Callers such as an enrollment
// coordinator must additionally require the returned state to be Stopped.
func InspectOwned(ctx context.Context, r Receipt) (Snapshot, error) {
	return inspectOwned(ctx, nativeBackend(), r)
}
func inspectOwned(ctx context.Context, b backend, r Receipt) (Snapshot, error) {
	s, snapshot, err := openOwned(ctx, b, r, readAccess, true)
	if err != nil {
		return Snapshot{}, err
	}
	defer s.Close()
	return snapshot, nil
}
func ApplyInstall(ctx context.Context, p InstallPlan) (Receipt, error) {
	return install(ctx, nativeBackend(), p)
}
func ApplyStart(ctx context.Context, r Receipt) (ApplyResult, error) {
	return apply(ctx, nativeBackend(), r, startAccess)
}
func ApplyStop(ctx context.Context, r Receipt) (ApplyResult, error) {
	return apply(ctx, nativeBackend(), r, stopAccess)
}
func ApplyUninstall(ctx context.Context, r Receipt) (ApplyResult, error) {
	return apply(ctx, nativeBackend(), r, deleteAccess)
}

func inspect(ctx context.Context, b backend) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s, err := b.Open(readAccess)
	if errors.Is(err, ErrNotInstalled) {
		return Snapshot{}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	defer s.Close()
	return s.Inspect()
}
func plan(ctx context.Context, b backend) (InstallPlan, error) {
	if err := ctx.Err(); err != nil {
		return InstallPlan{}, err
	}
	l, err := b.Layout()
	if err != nil {
		return InstallPlan{}, err
	}
	digest, err := b.VerifyExecutable(l)
	if err != nil {
		return InstallPlan{}, err
	}
	existing, err := inspect(ctx, b)
	if err != nil {
		return InstallPlan{}, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return InstallPlan{}, err
	}
	id := hex.EncodeToString(nonce[:])
	return InstallPlan{l, configuration(l, id, digest), digest, existing, id}, nil
}
func digestConfig(c Configuration) string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && s == strings.ToLower(s)
}
func validServiceSID(s string) bool {
	// A service SID has authority 5 and the service namespace RID 80 followed
	// by exactly five decimal SHA-1 words. Reject malformed/other namespaces.
	p := strings.Split(s, "-")
	if len(p) != 9 || strings.Join(p[:4], "-") != "S-1-5-80" {
		return false
	}
	for _, v := range p[4:] {
		if v == "" || len(v) > 10 || (len(v) > 1 && v[0] == '0') {
			return false
		}
		var n uint64
		for _, c := range v {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + uint64(c-'0')
			if n > 0xffffffff {
				return false
			}
		}
	}
	return true
}
func install(ctx context.Context, b backend, p InstallPlan) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	l, err := b.Layout()
	if err != nil {
		return Receipt{}, err
	}
	if l != p.Layout || !validHex(p.InstallationID, 16) || !validHex(p.ExecutableSHA256, 32) || !reflect.DeepEqual(p.Configuration, configuration(l, p.InstallationID, p.ExecutableSHA256)) {
		return Receipt{}, ErrMismatch
	}
	if p.Existing.Exists {
		return Receipt{}, ErrExisting
	}
	current, err := inspect(ctx, b)
	if err != nil {
		return Receipt{}, err
	}
	if current.Exists {
		return Receipt{}, ErrExisting
	}
	hash, err := b.VerifyExecutable(l)
	if err != nil {
		return Receipt{}, err
	}
	if hash != p.ExecutableSHA256 {
		return Receipt{}, ErrMismatch
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	r := Receipt{Version: 1, InstallationID: p.InstallationID, Layout: l, ConfigurationSHA256: digestConfig(p.Configuration), ExecutableSHA256: hash}
	s, err := b.Create(p.Configuration)
	if s != nil {
		defer s.Close()
	}
	if err != nil {
		return r, fmt.Errorf("service creation/configuration incomplete; retain installation intent and inspect: %w", err)
	}
	if s == nil {
		return r, errors.New("service creation returned no handle; retain installation intent")
	}
	sid, err := b.LookupSID()
	if err != nil {
		return r, err
	}
	if !validServiceSID(sid) {
		return r, ErrMismatch
	}
	r.ServiceSID = sid
	snapshot, err := s.Inspect()
	if err != nil {
		return r, err
	}
	if !snapshot.Exists || snapshot.State != Stopped || snapshot.ServiceSID != sid || !reflect.DeepEqual(snapshot.Configuration, p.Configuration) {
		return r, ErrMismatch
	}
	r.Complete = true
	return r, nil
}
func openOwned(ctx context.Context, b backend, r Receipt, a access, verifyBinary bool) (service, Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, Snapshot{}, err
	}
	l, err := b.Layout()
	if err != nil {
		return nil, Snapshot{}, err
	}
	c := configuration(l, r.InstallationID, r.ExecutableSHA256)
	if r.Version != 1 || !r.Complete || r.Layout != l || !validHex(r.InstallationID, 16) || !validHex(r.ExecutableSHA256, 32) || !validServiceSID(r.ServiceSID) || r.ConfigurationSHA256 != digestConfig(c) {
		return nil, Snapshot{}, ErrMismatch
	}
	s, err := b.Open(a)
	if err != nil {
		return nil, Snapshot{}, err
	}
	accepted := false
	defer func() {
		if !accepted {
			s.Close()
		}
	}()
	snapshot, err := s.Inspect()
	if err != nil {
		return nil, Snapshot{}, err
	}
	if !snapshot.Exists || snapshot.ServiceSID != r.ServiceSID || !reflect.DeepEqual(snapshot.Configuration, c) {
		return nil, Snapshot{}, ErrMismatch
	}
	if verifyBinary {
		hash, err := b.VerifyExecutable(l)
		if err != nil {
			return nil, Snapshot{}, err
		}
		if hash != r.ExecutableSHA256 {
			return nil, Snapshot{}, ErrMismatch
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, Snapshot{}, err
	}
	accepted = true
	return s, snapshot, nil
}

func apply(ctx context.Context, b backend, r Receipt, a access) (ApplyResult, error) {
	result := ApplyResult{StateRetained: true}
	s, snapshot, err := openOwned(ctx, b, r, a, a == startAccess)
	if err != nil {
		return result, err
	}
	defer s.Close()
	result.Snapshot = snapshot
	switch a {
	case startAccess:
		if snapshot.State == Running {
			return result, nil
		}
		if snapshot.State != Stopped {
			return result, errors.New("service transition already pending")
		}
		err = s.Start()
	case stopAccess:
		if snapshot.State == Stopped {
			return result, nil
		}
		if snapshot.State != Running {
			return result, errors.New("service transition already pending")
		}
		err = s.Stop()
	case deleteAccess:
		if snapshot.State != Stopped {
			return result, ErrNotStopped
		}
		err = s.Delete()
		if err == nil {
			result.DeletePending = true
		}
	default:
		return result, ErrMismatch
	}
	if err != nil {
		return result, err
	}
	result.Requested = true
	if a != deleteAccess {
		result.Snapshot, err = s.Inspect()
	}
	return result, err
}
