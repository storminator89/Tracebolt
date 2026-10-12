package windowsaction

import (
	"encoding/json"
	"localrmm/internal/windowsstate"
	"time"
)

func AuthorityOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"started.json", "policy.json", "receipt.json"}, Directories: []string{"ledger"}, LockName: "broker.lock", TempName: "broker.tmp", MaxBytes: MaxMessageBytes, Create: create}
}
func LedgerOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"ledger.json"}, LockName: "action.lock", TempName: "action.tmp", MaxBytes: 512 << 10, Create: create}
}

// InitializeCreateOnly is a source setup seam, never reachable through IPC or
// runtime opening. The separately authorized local coordinator must already
// verify the activated endpoint, reviewed public key, broker installation and
// per-target SCM rights. It cannot adopt even an empty existing authority root.
// The durable started fence lives outside the separately removable ledger.
func InitializeCreateOnly(path string, p Policy, now time.Time) error {
	return initializeCreateOnly(path, p, now, ReviewExistingSetup)
}
func initializeCreateOnly(path string, p Policy, now time.Time, review func(Policy) error) error {
	if ValidatePolicy(p) != nil || !p.Enabled || now.Unix() <= 0 || now.Unix() > 253402300799 {
		return ErrInvalid
	}
	expected, e := AuthorityPath()
	if e != nil || path != expected {
		return ErrInvalid
	}
	// Source setup performs read-only native review before any store creation.
	if e = review(p); e != nil {
		return e
	}
	root, e := windowsstate.Open(path, AuthorityOptions(p.BrokerSID, true))
	if e != nil {
		return e
	}
	defer root.Close()
	binding, _ := json.Marshal(p.Binding)
	if e = root.Write("started.json", binding); e != nil {
		return e
	}
	raw, _ := json.Marshal(p)
	if e = root.Write("policy.json", raw); e != nil {
		return e
	}
	state, e := root.CreateDirectoryStore("ledger", LedgerOptions(p.BrokerSID, true))
	if e != nil {
		return e
	}
	defer state.Close()
	raw, _ = json.Marshal(ledger{Version: LedgerVersion, Binding: p.Binding, ClockFloor: now.UTC().Unix(), Jobs: []record{}})
	if e = state.Write("ledger.json", raw); e != nil {
		return e
	}
	if e = state.Close(); e != nil {
		return e
	}
	if e = root.Write("receipt.json", binding); e != nil {
		return e
	}
	return root.Close()
}

func OpenNativeBroker() (*Broker, func() error, error) {
	sid, e := serviceSID(BrokerName)
	if e != nil {
		return nil, nil, e
	}
	agent, e := serviceSID(AgentName)
	if e != nil {
		return nil, nil, e
	}
	// Identity/process/token/thread/default-DACL checks precede all protected
	// authority, ledger, executable and action-capable target handle opens.
	if e = verifyBrokerProcess(Policy{BrokerSID: sid, AgentSID: agent}); e != nil {
		return nil, nil, e
	}
	path, e := AuthorityPath()
	if e != nil {
		return nil, nil, e
	}
	root, e := windowsstate.Open(path, AuthorityOptions(sid, false))
	if e != nil {
		return nil, nil, e
	}
	state, e := windowsstate.Open(path+`\ledger`, LedgerOptions(sid, false))
	if e != nil {
		root.Close()
		return nil, nil, e
	}
	close := func() error {
		a := state.Close()
		b := root.Close()
		if a != nil {
			return a
		}
		return b
	}
	b, e := NewBroker(root, state, nativeBackend(), func() time.Time { return time.Now().UTC() })
	if e != nil {
		close()
		return nil, nil, e
	}
	if e = verifyBrokerProcess(b.policy); e != nil {
		close()
		return nil, nil, e
	}
	if e = enableBrokerPeerQueries(b.policy); e != nil {
		close()
		return nil, nil, e
	}
	return b, close, nil
}
