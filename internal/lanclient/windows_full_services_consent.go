package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func windowsFullServicesDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-full-services"
}
func windowsFullServicesOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "full-services.lock", TempName: "full-services.tmp", MaxBytes: windowsfullservices.MaxPackBytes, Create: create}
}

type WindowsFullServicesConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// This function is reachable only through the independent stopped-owned-service
// CLI. It neither widens existing grants nor changes the original sender ledger.
func ConfigureWindowsFullServices(path, mode string, acknowledged, insecure bool) (WindowsFullServicesConsentResult, error) {
	zero := WindowsFullServicesConsentResult{}
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || insecure != (m.config.Profile == "http-test") || validateUpdatesActivatedMaterial(path, m) != nil {
		return zero, ErrConfiguration
	}
	main, e := lanclientstate.AcquireWindowsFullServicesInitialization(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer main.Close()
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, ErrState
	}
	out, e := updateWindowsFullServicesConsent(m.config.AgentID, m.binding, mode, func(create bool) (windowsfullservices.Storage, error) {
		return windowsstate.Open(windowsFullServicesDirectory(m), windowsFullServicesOptions(sid, create))
	}, func() time.Time { return time.Now().UTC() }, main)
	if e != nil || main.Close() != nil {
		return zero, ErrState
	}
	return out, nil
}
func updateWindowsFullServicesConsent(device, binding, mode string, open func(bool) (windowsfullservices.Storage, error), now func() time.Time, marker fullServicesUsedMarker) (WindowsFullServicesConsentResult, error) {
	zero := WindowsFullServicesConsentResult{}
	if open == nil || now == nil || marker == nil || mode != "preview" && mode != "enable" && mode != "disable" {
		return zero, ErrConfiguration
	}
	used, e := marker.Used()
	if e != nil {
		return zero, ErrState
	}
	st, e := open(false)
	fresh := false
	if errors.Is(e, os.ErrNotExist) && used {
		return zero, ErrState
	}
	if e == nil && !used {
		if st != nil {
			st.Close()
		}
		return zero, ErrState
	}
	if errors.Is(e, os.ErrNotExist) && mode == "enable" {
		if marker.Mark() != nil {
			return zero, ErrState
		}
		st, e = open(true)
		fresh = e == nil
	}
	if errors.Is(e, os.ErrNotExist) && mode != "enable" {
		return WindowsFullServicesConsentResult{windowsfullservices.Scope, false, true}, nil
	}
	if e != nil || st == nil {
		return zero, ErrState
	}
	defer st.Close()
	if fresh {
		if windowsfullservices.InitializeState(st, device, binding) != nil {
			return zero, ErrState
		}
	}
	state, e := windowsfullservices.OpenState(st, device, binding)
	if e != nil {
		return zero, ErrState
	}
	raw, e := st.Read("consent.json")
	var c windowsfullservices.Consent
	if e == nil {
		c, e = windowsfullservices.DecodeConsent(raw)
		if e == nil && c.SenderBinding != binding {
			e = ErrState
		}
	} else if fresh && errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	if e != nil {
		return zero, ErrState
	}
	change := mode == "enable" && !c.Enabled || mode == "disable" && c.Enabled
	if change {
		at := now().UTC()
		if !windowsfullservices.ValidTime(at) || !c.ChangedAt.IsZero() && at.Before(c.ChangedAt) || c.Revision == windowsfullservices.MaxSequence {
			return zero, ErrState
		}
		if mode == "enable" {
			var id [16]byte
			if _, e = rand.Read(id[:]); e != nil {
				return zero, ErrState
			}
			c = windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Revision: c.Revision + 1, Enabled: true, ChangedAt: at}
		} else {
			c.Enabled = false
			c.Revision++
			c.ChangedAt = at
		}
		raw, e = windowsfullservices.EncodeConsent(c)
		if e != nil || st.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return WindowsFullServicesConsentResult{windowsfullservices.Scope, c.Enabled, true}, nil
}

type fullServicesUsedMarker interface {
	Used() (bool, error)
	Mark() error
}
