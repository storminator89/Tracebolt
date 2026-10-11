package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsnetworkcontext"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func windowsNetworkContextDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-network-context"
}
func windowsNetworkContextOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "network-context.lock", TempName: "network-context.tmp", MaxBytes: windowsnetworkcontext.MaxPackBytes, Create: create}
}

type WindowsNetworkContextConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// This function is reachable only through the independent stopped-owned-service
// CLI or the exact fresh combined approval. It neither widens old grants nor
// changes the original telemetry counter or pending bytes.
func ConfigureWindowsNetworkContext(path, mode string, acknowledged, insecure bool) (WindowsNetworkContextConsentResult, error) {
	zero := WindowsNetworkContextConsentResult{}
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
	main, e := lanclientstate.AcquireWindowsNetworkContextInitialization(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer main.Close()
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, ErrState
	}
	out, e := updateWindowsNetworkContextConsent(m.config.AgentID, m.binding, mode, func(create bool) (windowsnetworkcontext.Storage, error) {
		return windowsstate.Open(windowsNetworkContextDirectory(m), windowsNetworkContextOptions(sid, create))
	}, func() time.Time { return time.Now().UTC() }, main)
	if e != nil || main.Close() != nil {
		return zero, ErrState
	}
	return out, nil
}
func updateWindowsNetworkContextConsent(device, binding, mode string, open func(bool) (windowsnetworkcontext.Storage, error), now func() time.Time, marker networkContextUsedMarker) (WindowsNetworkContextConsentResult, error) {
	zero := WindowsNetworkContextConsentResult{}
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
		return WindowsNetworkContextConsentResult{windowsnetworkcontext.Scope, false, true}, nil
	}
	if e != nil || st == nil {
		return zero, ErrState
	}
	defer st.Close()
	if fresh {
		if windowsnetworkcontext.InitializeState(st, device, binding) != nil {
			return zero, ErrState
		}
	}
	state, e := windowsnetworkcontext.OpenState(st, device, binding)
	if e != nil {
		return zero, ErrState
	}
	raw, e := st.Read("consent.json")
	var c windowsnetworkcontext.Consent
	if e == nil {
		c, e = windowsnetworkcontext.DecodeConsent(raw)
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
		if !windowsnetworkcontext.ValidTime(at) || !c.ChangedAt.IsZero() && at.Before(c.ChangedAt) || c.Revision == windowsnetworkcontext.MaxSequence {
			return zero, ErrState
		}
		if mode == "enable" {
			var id [16]byte
			if _, e = rand.Read(id[:]); e != nil {
				return zero, ErrState
			}
			c = windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Revision: c.Revision + 1, Enabled: true, ChangedAt: at}
		} else {
			c.Enabled = false
			c.Revision++
			c.ChangedAt = at
		}
		raw, e = windowsnetworkcontext.EncodeConsent(c)
		if e != nil || st.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return WindowsNetworkContextConsentResult{windowsnetworkcontext.Scope, c.Enabled, true}, nil
}

type networkContextUsedMarker interface {
	Used() (bool, error)
	Mark() error
}
