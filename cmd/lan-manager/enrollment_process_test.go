//go:build linux

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PTY fixture data arrives through this process's private stdin pipe, never
// arguments/environment. Only bounded pass/fail and public comparison metadata
// leave the helper; captured terminal contents are never printed.
const enrollmentPTY = `import json,os,pty,re,select,signal,sys,termios,time
cfg=json.load(sys.stdin)
pid,fd=pty.fork()
if pid==0:
 os.execv(cfg['args'][0],cfg['args'])
buf=b'';sent=False;deadline=time.monotonic()+50;status=None
try:
 while time.monotonic()<deadline:
  ready,_,_=select.select([fd],[],[],0.05)
  if ready:
   try: chunk=os.read(fd,4096)
   except OSError: chunk=b''
   if chunk: buf+=chunk
   if len(buf)>65536: break
  if not sent and b'invitation (hidden):' in buf:
   echo=bool(termios.tcgetattr(fd)[3]&termios.ECHO)
   fp=re.search(rb'Local device SPKI SHA-256: ([0-9a-f]{64})',buf)
   code=re.search(rb'Local 128-bit comparison: ([0-9a-f]{32})',buf)
   print(json.dumps({'phase':'prompt','echoDisabled':not echo,'fingerprint':fp.group(1).decode() if fp else '', 'comparison':code.group(1).decode() if code else ''}),flush=True)
   if echo: break
   os.write(fd,cfg['secret'].encode()+b'\n');sent=True
  done,st=os.waitpid(pid,os.WNOHANG)
  if done:
   status=os.waitstatus_to_exitcode(st);break
 if status is None:
  os.kill(pid,signal.SIGTERM)
  _,st=os.waitpid(pid,0);status=os.waitstatus_to_exitcode(st)
 stage=''
 stages={'preflight','prepare_account_and_paths','stage_verified_artifacts','enroll_as_dedicated_account','validate_existing_guided_state','publish_owned_binaries_and_unit','start_owned_service','commit'}
 for line in buf.splitlines():
  try:
   value=json.loads(line)
   if isinstance(value,dict) and value.get('committed') is False and value.get('identityRetained') is True and isinstance(value.get('plan'),dict):
    candidate=value.get('failureStage','preflight')
    if isinstance(candidate,str) and candidate in stages: stage=candidate
  except (ValueError,UnicodeError): pass
 print(json.dumps({'phase':'exit','exitCode':status,'secretEcho':cfg['secret'].encode() in buf,'ready':b'Enrollment handoff is ready.' in buf,'httpWarning':b'UNENCRYPTED HTTP TEST' in buf,'installerStage':stage}),flush=True)
finally:
 try: os.kill(pid,signal.SIGTERM)
 except ProcessLookupError: pass
 try: os.waitpid(pid,0)
 except ChildProcessError: pass
 os.close(fd)
`

type ptyEvent struct {
	Phase          string `json:"phase"`
	InstallerStage string `json:"installerStage"`
	EchoDisabled   bool   `json:"echoDisabled"`
	Fingerprint    string `json:"fingerprint"`
	Comparison     string `json:"comparison"`
	ExitCode       int    `json:"exitCode"`
	SecretEcho     bool   `json:"secretEcho"`
	Ready          bool   `json:"ready"`
	HTTPWarning    bool   `json:"httpWarning"`
}

func stopFixtureProcess(t *testing.T, cmd *exec.Cmd, done <-chan error) {
	t.Helper()
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case e := <-done:
		if e != nil {
			t.Error("fixture process did not stop cleanly")
		}
	case <-time.After(8 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Error("fixture process shutdown timeout")
	}
}
func TestGuidedThreeBinaryEnrollmentAndForeground(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("Python standard-library PTY helper unavailable; native CLI gate not executed")
	}
	binaries := map[string]string{}
	for _, name := range []string{"lan-manager", "enroll-agent", "lan-agent"} {
		path := filepath.Join(t.TempDir(), name)
		build := exec.Command("go", "build", "-buildvcs=false", "-o", path, "../"+name)
		if build.Run() != nil {
			t.Fatal("native fixture binary build failed", name)
		}
		binaries[name] = path
	}
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, enrolled, enrollmentPath := guidedFixture(t, profile)
			configPath := filepath.Join(t.TempDir(), "lan.json")
			config, _ := json.Marshal(m.Config)
			if os.WriteFile(configPath, config, 0600) != nil {
				t.Fatal("runtime config fixture")
			}
			manager := exec.Command(binaries["lan-manager"], "--lan-config", configPath, "--enrollment-config", enrollmentPath)
			if manager.Start() != nil {
				t.Fatal("native manager start")
			}
			managerDone := make(chan error, 1)
			go func() { managerDone <- manager.Wait() }()
			defer stopFixtureProcess(t, manager, managerDone)
			roots := x509.NewCertPool()
			if profile == lanconfig.TLS && !roots.AppendCertsFromPEM([]byte(enrolled.ServerCAPEM())) {
				t.Fatal("explicit operator root")
			}
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
			defer transport.CloseIdleConnections()
			jar, _ := cookiejar.New(nil)
			operator := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			deadline := time.Now().Add(8 * time.Second)
			ready := false
			for time.Now().Before(deadline) {
				response, e := operator.Get(m.Config.OperatorOrigin + "/api/auth/session")
				if e == nil {
					response.Body.Close()
					ready = response.StatusCode == 200
					if ready {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("guided runtime not ready")
			}
			call := func(path string, body any, csrf string) (int, []byte) {
				raw, _ := json.Marshal(body)
				r, _ := http.NewRequest("POST", m.Config.OperatorOrigin+path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", m.Config.OperatorOrigin)
				if csrf != "" {
					r.Header.Set("X-CSRF-Token", csrf)
				}
				response, e := operator.Do(r)
				if e != nil {
					t.Fatal("operator fixture request")
				}
				defer response.Body.Close()
				b, e := io.ReadAll(io.LimitReader(response.Body, 128*1024))
				if e != nil {
					t.Fatal("operator fixture response")
				}
				return response.StatusCode, b
			}
			get := func(path string, out any) {
				response, e := operator.Get(m.Config.OperatorOrigin + path)
				if e != nil {
					t.Fatal("operator fixture read")
				}
				defer response.Body.Close()
				if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 128*1024)).Decode(out) != nil {
					t.Fatal("operator fixture read contract")
				}
			}
			status, body := call("/api/auth/login", map[string]string{"password": "fixture-password-only"}, "")
			var session struct{ CSRFToken string }
			if status != 200 || json.Unmarshal(body, &session) != nil || session.CSRFToken == "" {
				t.Fatal("operator fixture login")
			}
			status, body = call("/api/enrollment/invitations", map[string]string{"requestId": "request_" + strings.Repeat("8", 32), "platform": "linux"}, session.CSRFToken)
			var created struct {
				Snapshot         enrollmentstate.Snapshot `json:"snapshot"`
				InvitationSecret string                   `json:"invitationSecret"`
				Bootstrap        api.EnrollmentBootstrap  `json:"bootstrap"`
			}
			if status != 201 || json.Unmarshal(body, &created) != nil || len(created.InvitationSecret) != 43 {
				t.Fatal("invitation fixture failed")
			}
			bootstrapPath := filepath.Join(t.TempDir(), "bootstrap.json")
			raw, _ := json.Marshal(created.Bootstrap)
			if bytes.Contains(raw, []byte(created.InvitationSecret)) || os.WriteFile(bootstrapPath, raw, 0600) != nil {
				t.Fatal("public bootstrap fixture")
			}
			stateDir := filepath.Join(t.TempDir(), "endpoint")
			args := []string{binaries["enroll-agent"], "--bootstrap", bootstrapPath, "--state-directory", stateDir, "--timeout", "45s"}
			if profile == lanconfig.HTTPTest {
				args = append(args, "--insecure-http-test")
			}
			input, _ := json.Marshal(map[string]any{"args": args, "secret": created.InvitationSecret})
			defer clear(input)
			enrollment := exec.Command(python, "-c", enrollmentPTY)
			enrollment.Stdin = bytes.NewReader(input)
			stdout, e := enrollment.StdoutPipe()
			if e != nil || enrollment.Start() != nil {
				t.Fatal("native PTY fixture start")
			}
			events := make(chan ptyEvent, 4)
			go func() {
				defer close(events)
				scan := bufio.NewScanner(io.LimitReader(stdout, 8192))
				for scan.Scan() {
					var event ptyEvent
					if json.Unmarshal(scan.Bytes(), &event) != nil {
						return
					}
					events <- event
				}
			}()
			enrollmentDone := make(chan error, 1)
			go func() { enrollmentDone <- enrollment.Wait() }()
			enrollmentWaited := false
			defer func() {
				if !enrollmentWaited {
					_ = enrollment.Process.Signal(os.Interrupt)
					select {
					case <-enrollmentDone:
					case <-time.After(8 * time.Second):
						enrollment.Process.Kill()
						<-enrollmentDone
					}
				}
			}()
			var prompt ptyEvent
			select {
			case prompt = <-events:
			case <-time.After(15 * time.Second):
				t.Fatal("native hidden prompt timeout")
			}
			if prompt.Phase != "prompt" || !prompt.EchoDisabled || len(prompt.Fingerprint) != 64 || len(prompt.Comparison) != 32 {
				t.Fatal("native trust display or hidden prompt failed")
			}
			var pending enrollmentstate.Snapshot
			deadline = time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				var view struct{ Items []enrollmentstate.Snapshot }
				get("/api/enrollment", &view)
				if len(view.Items) == 1 && view.Items[0].State == enrollmentstate.ClaimedPending {
					pending = view.Items[0]
					break
				}
				time.Sleep(40 * time.Millisecond)
			}
			if pending.State != enrollmentstate.ClaimedPending || pending.Claim.KeyFingerprint != prompt.Fingerprint || pending.Claim.ComparisonCode != prompt.Comparison {
				t.Fatal("local comparison does not match pending claim")
			}
			status, _ = call("/api/enrollment/"+pending.InvitationID+"/approve", map[string]any{"requestId": "request_" + strings.Repeat("9", 32), "expectedRevision": pending.Revision, "expectedKeyFingerprint": prompt.Fingerprint}, session.CSRFToken)
			if status != 200 {
				t.Fatal("native fixture approval")
			}
			var outcome ptyEvent
			select {
			case outcome = <-events:
			case <-time.After(30 * time.Second):
				t.Fatal("native enrollment completion timeout")
			}
			if outcome.Phase != "exit" || outcome.ExitCode != 0 || outcome.SecretEcho || !outcome.Ready || outcome.HTTPWarning != (profile == lanconfig.HTTPTest) {
				t.Fatal("native enrollment or private terminal boundary failed")
			}
			enrollmentWaited = true
			if e := <-enrollmentDone; e != nil {
				t.Fatal("PTY helper failed")
			}
			for _, name := range []string{"ledger.json", "agent.json", "ready.json"} {
				raw, e := os.ReadFile(filepath.Join(stateDir, name))
				if e != nil || bytes.Contains(raw, []byte(created.InvitationSecret)) {
					t.Fatal("native secret retention/handoff failure")
				}
			}
			var senderConfig lanclient.Config
			configBytes, readError := os.ReadFile(filepath.Join(stateDir, "agent.json"))
			if readError != nil || json.Unmarshal(configBytes, &senderConfig) != nil || senderConfig.SchemaVersion != lanclient.GuidedConfigVersion || lanclient.ValidateGuidedState(senderConfig) != nil {
				t.Fatal("guided existing-ledger handoff missing")
			}
			sender := exec.Command(binaries["lan-agent"], "--config", filepath.Join(stateDir, "agent.json"), "--foreground", "--interval", "15s")
			stream, e := sender.StdoutPipe()
			if e != nil || sender.Start() != nil {
				t.Fatal("native foreground start")
			}
			senderDone := make(chan error, 1)
			go func() { senderDone <- sender.Wait() }()
			senderStopped := false
			defer func() {
				if !senderStopped {
					stopFixtureProcess(t, sender, senderDone)
				}
			}()
			sent := make(chan agentloop.Event, 8)
			go func() {
				defer close(sent)
				scanner := bufio.NewScanner(stream)
				for scanner.Scan() {
					var line struct {
						SchemaVersion string          `json:"schemaVersion"`
						Event         agentloop.Event `json:"event"`
					}
					if json.Unmarshal(scanner.Bytes(), &line) != nil || line.SchemaVersion != "tracebolt.agent-loop.v1" {
						return
					}
					if line.Event.Phase == agentloop.Finished {
						sent <- line.Event
					}
				}
			}()
			var firstSeen, lastSeen time.Time
			for n := uint64(1); n <= 2; n++ {
				select {
				case event, ok := <-sent:
					if !ok || event.Outcome != agentloop.Success || event.Metadata.Sequence != n {
						t.Fatal("foreground delivery sequence failed")
					}
				case <-time.After(25 * time.Second):
					t.Fatal("foreground cadence timeout")
				}
				var inventory struct{ Items []model.Device }
				get("/api/devices", &inventory)
				if len(inventory.Items) != 1 || inventory.Items[0].Source != "lan" || inventory.Items[0].Synthetic || inventory.Items[0].Status != "unknown" || inventory.Items[0].LastSeen.IsZero() {
					t.Fatal("actual enrolled inventory missing")
				}
				if n == 1 {
					firstSeen = inventory.Items[0].LastSeen
				} else if !inventory.Items[0].LastSeen.After(firstSeen) {
					t.Fatal("scheduled report did not advance collection time")
				}
				lastSeen = inventory.Items[0].LastSeen
			}
			stopFixtureProcess(t, sender, senderDone)
			senderStopped = true
			var view struct{ Items []enrollmentstate.Snapshot }
			get("/api/enrollment", &view)
			if len(view.Items) != 1 || view.Items[0].State != enrollmentstate.Activated {
				t.Fatal("activation state missing")
			}
			active := view.Items[0]
			status, _ = call("/api/enrollment/"+active.InvitationID+"/terminate", map[string]any{"requestId": "request_" + strings.Repeat("a", 32), "expectedRevision": active.Revision, "action": "revoked"}, session.CSRFToken)
			if status != 200 {
				t.Fatal("guided revocation failed")
			}
			denied := exec.Command(binaries["lan-agent"], "--config", filepath.Join(stateDir, "agent.json"))
			if denied.Run() == nil {
				t.Fatal("revoked native sender was accepted")
			}
			var afterRevoke struct{ Items []model.Device }
			get("/api/devices", &afterRevoke)
			if len(afterRevoke.Items) != 1 || !afterRevoke.Items[0].LastSeen.Equal(lastSeen) {
				t.Fatal("rejected delivery refreshed observation age")
			}
			t.Log("PASS: three native binaries, hidden invitation input, local comparison, approval, activation, two scheduled real Linux observations, revocation; no service installation")
		})
	}
}
