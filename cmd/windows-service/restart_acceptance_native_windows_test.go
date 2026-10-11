//go:build windows && tracebolt_restart_acceptance && !tracebolt_fresh_native && !tracebolt_setup_native

package main

// This controller is absent from every ordinary executable. The only effects it
// can request are exactly two ordinary installed --restart --apply invocations,
// with the second unreachable unless the real installer-lock refusal is proved.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/restartgate"
	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
)

// The manual source-pinned build must supply all three linker values. No plan
// can fill an empty compiled binding or turn an ordinary test into native proof.
var restartCompiledSourceCommit string
var restartCompiledSourceTree string
var restartCompiledSourceInventory string

func TestOwnRestartNativeAcceptance(t *testing.T) {
	if !restartNativeArguments(os.Args) || restartCIEnvironment() {
		t.Fatal("native acceptance entry denied")
	}
	p, e := restartParsePlan([]byte(os.Getenv("TRACEBOLT_RESTART_PLAN")), time.Now())
	if e != nil || p.ControllerSourceCommit != restartCompiledSourceCommit || p.ControllerSourceTree != restartCompiledSourceTree || p.ControllerSourceInventorySHA256 != restartCompiledSourceInventory {
		t.Fatal("native acceptance authority denied")
	}
	pipe, e := restartReportPipe()
	if e != nil {
		t.Fatal("native acceptance private report channel denied")
	}
	defer pipe.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cancelPipe, e := restartInheritedPipe("TRACEBOLT_RESTART_CANCEL_HANDLE")
	if e != nil {
		t.Fatal("native acceptance cancellation channel denied")
	}
	defer cancelPipe.Close()
	go func() { var one [1]byte; _, _ = cancelPipe.Read(one[:]); cancel() }()
	r := restartAcceptanceReport{Schema: "tracebolt.windows-own-restart-controller-result.v1", RunID: p.RunID, PlanSHA256: p.PlanSHA256, BrowserBaselineSHA256: p.BrowserBaselineSHA256, Status: "blocked", Phase: "authorization", DeviceID: p.DeviceID, CertificateSHA256: p.CertificateSHA256, InstalledSHA256: p.InstalledSHA256, ControllerSHA256: p.ControllerSHA256}
	// Only this private pipe is authoritative. Go PASS, test exit status, console
	// diagnostics, supplied files and human-authored flags never set these checks.
	unknown := false
	emitted := false
	// A finite queue keeps uncertainty publication independent of pipe backpressure.
	// There are at most two messages, and neither can acquire a command capability.
	reports := make(chan []byte, 2)
	written := make(chan bool, 1)
	go func() {
		ok := true
		for b := range reports {
			n, e := pipe.Write(b)
			if e != nil || n != len(b) {
				ok = false
				cancel()
			}
		}
		written <- ok
	}()
	emit := func() bool {
		b, e := json.Marshal(r)
		if e != nil || len(b) > 8192 {
			return false
		}
		b = append(b, '\n')
		select {
		case reports <- b:
			return true
		default:
			return false
		}
	}
	uncertainty := func(_ string) {
		unknown = true
		r.Status = "unknown-intervention-required"
		if !emitted {
			emitted = true
			if !emit() {
				cancel()
			}
		}
	}
	if restartExecute(ctx, p, &r, uncertainty) != nil {
		if r.CommandInvocations > 0 {
			unknown = true
		}
		if unknown {
			r.Status = "unknown-intervention-required"
		} else {
			r.Status = "blocked"
		}
	} else if !unknown {
		r.Status = "passed-native-subset"
		r.Phase = "complete"
	}
	if !emit() {
		close(reports)
		t.Fatal("native acceptance private result unavailable")
	}
	close(reports)
	if !<-written {
		t.Fatal("native acceptance private result unavailable")
	}
	if r.Status != "passed-native-subset" {
		t.Fatal("native acceptance subset incomplete")
	}
}

func restartCIEnvironment() bool { return restartRejectCI(os.Environ()) }
func restartReportPipe() (*os.File, error) {
	return restartInheritedPipe("TRACEBOLT_RESTART_REPORT_HANDLE")
}
func restartInheritedPipe(env string) (*os.File, error) {
	raw := os.Getenv(env)
	n, e := strconv.ParseUint(raw, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != raw || uint64(uintptr(n)) != n {
		return nil, restartAcceptanceRejected
	}
	h := windows.Handle(n)
	current, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return nil, restartAcceptanceRejected
	}
	user, e := current.GetTokenUser()
	current.Close()
	if e != nil || user.User.Sid == nil {
		return nil, restartAcceptanceRejected
	}
	if !restartPipePrivate(h, user.User.Sid.String()) {
		return nil, restartAcceptanceRejected
	}
	kind, e := windows.GetFileType(h)
	if e != nil || kind != windows.FILE_TYPE_PIPE {
		return nil, restartAcceptanceRejected
	}
	var flags uint32
	if !restartHandleInformation(h, &flags) || flags&windows.HANDLE_FLAG_INHERIT == 0 {
		return nil, restartAcceptanceRejected
	}
	// A write-only inherited endpoint is consumed once. The supervisor's child
	// must never receive the reporting capability, even while the pipe is drained.
	if windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, 0) != nil {
		return nil, restartAcceptanceRejected
	}
	return os.NewFile(uintptr(h), "<private restart report>"), nil
}

type restartClockPoint struct {
	ticks uint64
	mono  time.Time
}

func restartClock() (restartClockPoint, error) {
	before := time.Now()
	var ft windows.Filetime
	windows.GetSystemTimePreciseAsFileTime(&ft)
	after := time.Now()
	if after.Sub(before) > 20*time.Millisecond {
		return restartClockPoint{}, restartAcceptanceRejected
	}
	return restartClockPoint{uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime), after}, nil
}
func restartClockValid(a, b restartClockPoint) bool {
	return restartClockCoherent(a.ticks, b.ticks, b.mono.Sub(a.mono))
}
func restartFiletimeUTC(v uint64) string {
	const epoch = uint64(116444736000000000)
	if v < epoch {
		return ""
	}
	v -= epoch
	return time.Unix(int64(v/10000000), int64(v%10000000)*100).UTC().Format(time.RFC3339Nano)
}

func restartExecute(ctx context.Context, p restartAcceptancePlan, r *restartAcceptanceReport, unknown func(string)) (retErr error) {
	deadline, _ := time.Parse(time.RFC3339, p.ExpiresAt)
	guard := func() bool {
		_, e := restartParsePlan([]byte(os.Getenv("TRACEBOLT_RESTART_PLAN")), time.Now())
		return e == nil && ctx.Err() == nil && !restartCIEnvironment() && time.Now().Before(deadline)
	}
	// Capture immutable approval values. Environment replacement cannot amend it.
	initialRaw := os.Getenv("TRACEBOLT_RESTART_PLAN")
	originalGuard := guard
	guard = func() bool { return os.Getenv("TRACEBOLT_RESTART_PLAN") == initialRaw && originalGuard() }
	if !guard() || restartTarget(p) != nil {
		return restartAcceptanceRejected
	}
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return restartAcceptanceRejected
	}
	user, e := token.GetTokenUser()
	elevated := token.IsElevated()
	token.Close()
	if e != nil || !elevated || user.User.Sid == nil {
		return restartAcceptanceRejected
	}
	operator := user.User.Sid.String()
	pins := &restartPins{}
	defer func() {
		if e := pins.close(); e != nil && retErr == nil {
			retErr = e
		}
	}()
	workspace, e := pins.open(p.Workspace, true, operator, "", 0)
	if e != nil {
		return e
	}
	if !restartPrivateACL(workspace.handle, operator) {
		return restartAcceptanceRejected
	}
	self, e := os.Executable()
	if e != nil || !windowspath.Canonical(self) {
		return restartAcceptanceRejected
	}
	ownImage, e := pins.open(self, false, operator, "", 128<<20)
	if e != nil || ownImage.digest != p.ControllerSHA256 {
		return restartAcceptanceRejected
	}
	// One target-local, session-independent exclusion. No lifecycle right, job,
	// kill-on-close policy, or cleanup/compensation operation is acquired.
	sd, e := windows.SecurityDescriptorFromString("O:" + operator + "G:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + operator + ")")
	if e != nil {
		return restartAcceptanceRejected
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	mutex, e := windows.CreateMutex(&sa, true, windows.StringToUTF16Ptr(`Global\TraceboltOwnRestartNativeAcceptance`))
	if e != nil {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return restartAcceptanceRejected
	}
	defer func() {
		if windows.ReleaseMutex(mutex) != nil && retErr == nil {
			retErr = restartAcceptanceRejected
		}
		if windows.CloseHandle(mutex) != nil && retErr == nil {
			retErr = restartAcceptanceRejected
		}
	}()
	if !guard() || restartRecord(workspace, operator, p, "started") != nil {
		return restartAcceptanceRejected
	}
	r.Phase = "baseline"
	layout, store, e := openReceiptStore()
	if store != nil {
		defer func() {
			if store != nil && store.Close() != nil && retErr == nil {
				retErr = restartAcceptanceRejected
			}
		}()
	}
	if e != nil || store == nil {
		return restartAcceptanceRejected
	}
	raw, e := store.Read("receipt.json")
	defer clear(raw)
	if e != nil || restartHash(raw) != p.ReceiptSHA256 {
		return restartAcceptanceRejected
	}
	receipt, e := decodeInstallReceipt(raw, layout)
	if e != nil || receipt.Service.ExecutableSHA256 != p.InstalledSHA256 {
		return restartAcceptanceRejected
	}
	intent, e := store.Read("intent.json")
	defer clear(intent)
	if e != nil || restartHash(intent) != p.IntentSHA256 || store.Verify() != nil {
		return restartAcceptanceRejected
	}
	// Keep metadata identity/ACL bindings for the two installer ownership records
	// across lease release as well as comparing their exact bytes through Store.
	for _, record := range []struct{ name, digest string }{{"receipt.json", p.ReceiptSHA256}, {"intent.json", p.IntentSHA256}} {
		pin, e := pins.open(filepath.Join(installerPath(layout), record.name), false, "", "", 64<<10)
		if e != nil || pin.digest != record.digest {
			return restartAcceptanceRejected
		}
	}
	image, e := pins.open(layout.Executable, false, "", "", 128<<20)
	if e != nil || image.digest != p.InstalledSHA256 {
		return restartAcceptanceRejected
	}
	observer, e := restartOpenObserver(receipt.Service)
	if e != nil {
		return restartAcceptanceRejected
	}
	defer func() {
		if observer.close() != nil && retErr == nil {
			retErr = restartAcceptanceRejected
		}
	}()
	old, e := observer.process()
	if e != nil {
		return restartAcceptanceRejected
	}
	defer func() {
		if old.close() != nil && retErr == nil {
			retErr = restartAcceptanceRejected
		}
	}()
	r.OldProcessGenerationSHA256 = old.generation()
	public, e := restartReadPublic(p, layout, receipt.Service.ServiceSID, pins)
	if e != nil || !observer.same(old) {
		return restartAcceptanceRejected
	}
	baseClock, e := restartClock()
	if e != nil {
		return e
	}
	verifyLease := func() bool {
		a, e := store.Read("receipt.json")
		defer clear(a)
		b, f := store.Read("intent.json")
		defer clear(b)
		return e == nil && f == nil && bytes.Equal(a, raw) && bytes.Equal(b, intent) && store.Verify() == nil
	}
	sequence := restartgate.NewSequence()
	r.Phase = "contention"
	if !guard() || !observer.same(old) || !verifyLease() || pins.verify() != nil || restartRecord(workspace, operator, p, "negative.intent") != nil || !guard() || !pins.launchReady() || sequence.BeginRejection() != nil {
		return restartAcceptanceRejected
	}
	r.CommandInvocations++
	command, e := restartgate.Supervise(ctx, layout.Executable, deadline, func(s string) { sequence.MarkUnknown(); unknown(s) })
	if e != nil || sequence.ConfirmRejection(command, observer.same(old), verifyLease()) != nil {
		return restartAcceptanceRejected
	}
	r.InstallerContentionRefused = true
	r.Phase = "lease-release"
	release := store.Close()
	store = nil
	if sequence.ReleaseLease(release == nil) != nil {
		return restartAcceptanceRejected
	}
	before, e := restartClock()
	if e != nil || !restartClockValid(baseClock, before) || !guard() || !observer.same(old) || pins.verify() != nil {
		return restartAcceptanceRejected
	}
	// Public artifact handles remain held; no enrollment, sender, ledger, grant,
	// or body store is opened while either service generation is alive.
	if !public.valid() {
		return restartAcceptanceRejected
	}
	r.Phase = "restart"
	if restartRecord(workspace, operator, p, "restart.intent") != nil || !guard() || !pins.launchReady() || sequence.BeginRestart() != nil {
		return restartAcceptanceRejected
	}
	start, e := restartClock()
	if e != nil || !restartClockValid(baseClock, start) {
		sequence.MarkUnknown()
		return restartAcceptanceRejected
	}
	r.WindowStartFiletime = strconv.FormatUint(start.ticks, 10)
	r.CommandInvocations++
	command, e = restartgate.Supervise(ctx, layout.Executable, deadline, func(s string) { sequence.MarkUnknown(); unknown(s) })
	if e != nil || sequence.ConfirmRestart(command) != nil || !sequence.Ready() {
		return restartAcceptanceRejected
	}
	r.Phase = "old-process-exit"
	for {
		state, e := windows.WaitForSingleObject(old.handle, 0)
		if e != nil {
			return restartAcceptanceRejected
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if state != uint32(windows.WAIT_TIMEOUT) || !guard() {
			return restartAcceptanceRejected
		}
		time.Sleep(20 * time.Millisecond)
	}
	var oldExit uint32
	if windows.GetExitCodeProcess(old.handle, &oldExit) != nil {
		return restartAcceptanceRejected
	}
	r.OldExitCode = &oldExit
	r.OldProcessExited = true
	if oldExit != 0 {
		return restartAcceptanceRejected
	}
	r.Phase = "new-process"
	current, e := observer.process()
	if e != nil {
		return restartAcceptanceRejected
	}
	defer func() {
		if current.close() != nil && retErr == nil {
			retErr = restartAcceptanceRejected
		}
	}()
	finish, e := restartClock()
	if e != nil || !restartClockValid(start, finish) || !restartClockValid(baseClock, finish) || !restartNewGeneration(restartGeneration{old.pid, old.created}, restartGeneration{current.pid, current.created}, start.ticks, finish.ticks) || !guard() {
		return restartAcceptanceRejected
	}
	r.NewRunningProcess = true
	r.NewProcessCreationFiletime = strconv.FormatUint(current.created, 10)
	r.NewProcessCreationUTC = restartFiletimeUTC(current.created)
	r.NewProcessGenerationSHA256 = current.generation()
	r.WindowEndFiletime = strconv.FormatUint(finish.ticks, 10)
	r.Phase = "retention"
	afterLayout, after, e := openReceiptStore()
	if after != nil {
		defer func() {
			if after != nil && after.Close() != nil && retErr == nil {
				retErr = restartAcceptanceRejected
			}
		}()
	}
	if e != nil || after == nil || afterLayout != layout {
		return restartAcceptanceRejected
	}
	a, e := after.Read("receipt.json")
	defer clear(a)
	b, f := after.Read("intent.json")
	defer clear(b)
	if e != nil || f != nil || !bytes.Equal(a, raw) || !bytes.Equal(b, intent) || after.Verify() != nil {
		return restartAcceptanceRejected
	}
	release = after.Close()
	after = nil
	if release != nil || pins.verify() != nil || !public.valid() || !observer.same(current) || !guard() {
		return restartAcceptanceRejected
	}
	r.ReceiptPublicIdentityRetained = true
	return nil
}

func restartTarget(p restartAcceptancePlan) error {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return restartAcceptanceRejected
	}
	guid, _, e := k.GetStringValue("MachineGuid")
	closed := k.Close()
	v := windows.RtlGetVersion()
	if runtime.GOARCH != "amd64" || !restartInteractiveDesktop() {
		return restartAcceptanceRejected
	}
	if e != nil || closed != nil || restartHash([]byte(strings.ToLower(strings.TrimSpace(guid)))) != p.MachineID || v == nil || strconv.FormatUint(uint64(v.BuildNumber), 10) != p.OSBuild || v.MajorVersion != 10 || v.BuildNumber != 26100 || v.ProductType != 3 {
		return restartAcceptanceRejected
	}
	return nil
}

func restartRecord(dir *restartPinned, owner string, p restartAcceptancePlan, phase string) error {
	if dir.check() != nil {
		return restartAcceptanceRejected
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + owner + "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + owner + ")")
	if e != nil {
		return restartAcceptanceRejected
	}
	h, e := windowspath.CreateChild(dir.handle, p.RunID+"."+phase+".json", false, sd)
	if e != nil {
		return restartAcceptanceRejected
	}
	f := os.NewFile(uintptr(h), "<restart create-only intent>")
	if f == nil {
		windows.CloseHandle(h)
		return restartAcceptanceRejected
	}
	b, _ := json.Marshal(struct {
		Schema     string `json:"schema"`
		RunID      string `json:"runId"`
		PlanSHA256 string `json:"planSHA256"`
		Phase      string `json:"phase"`
	}{"tracebolt.windows-own-restart-intent.v1", p.RunID, p.PlanSHA256, phase})
	n, e := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || n != len(b) || syncErr != nil || closeErr != nil || dir.check() != nil {
		return restartAcceptanceRejected
	}
	return nil
}

type restartPublic struct{ pins []*restartPinned }

func (p restartPublic) valid() bool {
	for _, f := range p.pins {
		if f.check() != nil {
			return false
		}
	}
	return true
}
func restartReadPublic(p restartAcceptancePlan, l windowsservice.Layout, sid string, pins *restartPins) (restartPublic, error) {
	var out restartPublic
	specs := []struct {
		path, hash string
		max        int64
	}{{filepath.Join(l.StateRoot, "bootstrap.json"), p.PublicSHA256.Bootstrap, 64 << 10}, {filepath.Join(l.EnrollmentRoot, "agent.json"), p.PublicSHA256.Config, 64 << 10}, {filepath.Join(l.EnrollmentRoot, "ready.json"), p.PublicSHA256.Ready, 4096}, {filepath.Join(l.EnrollmentRoot, "agent-cert.pem"), p.PublicSHA256.Certificate, 32 << 10}}
	raw := make([][]byte, 4)
	defer func() {
		for _, b := range raw {
			clear(b)
		}
	}()
	for i, s := range specs {
		f, e := pins.open(s.path, false, "", sid, s.max)
		if e != nil || f.digest != s.hash {
			return out, restartAcceptanceRejected
		}
		out.pins = append(out.pins, f)
		raw[i], e = f.read(s.max)
		if e != nil {
			return out, e
		}
	}
	bootstrap, e := enrollmentclient.ParseBootstrap(raw[0])
	if e != nil || bootstrap.Profile != "tls" || bootstrap.CollectionProfile != "windows-inventory-v1" || bootstrap.ManagerInstanceID != p.ManagerInstanceID || bootstrap.AgentOrigin != p.AgentOrigin || bootstrap.EnrollmentOrigin != p.EnrollmentOrigin {
		return out, restartAcceptanceRejected
	}
	var config lanclient.Config
	if restartStrictJSON(raw[1], &config, 64<<10) != nil || config.Validate() != nil || config.SchemaVersion != lanclient.WindowsInventoryConfigVersion || config.CollectionProfile != "windows-inventory-v1" || config.Profile != "tls" || config.InsecureHTTPAcknowledged || config.ManagerOrigin != p.AgentOrigin || config.AgentID != p.DeviceID || config.CertificateFile != specs[3].path || config.PrivateKeyFile != filepath.Join(l.EnrollmentRoot, "agent-key.pem") || config.ServerCAFile != filepath.Join(l.EnrollmentRoot, "server-ca.pem") || config.StateDirectory != l.SenderRoot {
		return out, restartAcceptanceRejected
	}
	var ready struct {
		Version             string `json:"version"`
		ConfigHash          string `json:"configHash"`
		CertificateHash     string `json:"certificateHash"`
		ServerAuthenticated bool   `json:"serverAuthenticated"`
	}
	if restartStrictJSON(raw[2], &ready, 4096) != nil || ready.Version != "tracebolt.enrollment-ready.v2" || !ready.ServerAuthenticated || ready.ConfigHash != restartHash(raw[1]) || ready.CertificateHash != p.CertificateSHA256 {
		return out, restartAcceptanceRejected
	}
	block, rest := pem.Decode(raw[3])
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || restartHash(block.Bytes) != p.CertificateSHA256 {
		return out, restartAcceptanceRejected
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) || cert.Subject.CommonName != p.DeviceID || cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || cert.SignatureAlgorithm != x509.PureEd25519 {
		return out, restartAcceptanceRejected
	}
	issuerBlock, _ := pem.Decode([]byte(bootstrap.IssuerPEM))
	if issuerBlock == nil {
		return out, restartAcceptanceRejected
	}
	issuer, e := x509.ParseCertificate(issuerBlock.Bytes)
	if e != nil || cert.CheckSignatureFrom(issuer) != nil {
		return out, restartAcceptanceRejected
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bootstrap.IssuerRootPEM)) || !intermediates.AppendCertsFromPEM([]byte(bootstrap.IssuerPEM)) {
		return out, restartAcceptanceRejected
	}
	if _, e := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return out, restartAcceptanceRejected
	}
	// Any chain tail must be public certificates only, never a hidden private key.
	for len(bytes.TrimSpace(rest)) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return out, restartAcceptanceRejected
		}
		if _, e = x509.ParseCertificate(b.Bytes); e != nil {
			return out, restartAcceptanceRejected
		}
	}
	return out, nil
}

// A present, visible interactive window station and a non-service session are
// mandatory even when an external approval reference has the correct shape.
func restartInteractiveDesktop() bool {
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session == 0 {
		return false
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	station, _, _ := user32.NewProc("GetProcessWindowStation").Call()
	if station == 0 {
		return false
	}
	var flags struct {
		Inherit  int32
		Reserved int32
		Flags    uint32
	}
	var needed uint32
	ok, _, _ := user32.NewProc("GetUserObjectInformationW").Call(station, 1, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), uintptr(unsafe.Pointer(&needed)))
	return ok != 0 && needed == uint32(unsafe.Sizeof(flags)) && flags.Flags&1 != 0
}

func restartHandleInformation(h windows.Handle, flags *uint32) bool {
	ok, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation").Call(uintptr(h), uintptr(unsafe.Pointer(flags)))
	return ok != 0
}

func restartPipePrivate(h windows.Handle, owner string) bool {
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil || !sd.IsValid() {
		return false
	}
	own, _, e := sd.Owner()
	if e != nil || own == nil || !restartTrusted(own.String(), owner, "") {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return false
	}
	return restartACLRejects(acl, ^uint32(0), func(s string) bool { return s == owner || s == "S-1-5-18" || s == "S-1-5-32-544" })
}
