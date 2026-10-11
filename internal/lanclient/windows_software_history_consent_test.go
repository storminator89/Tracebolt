package lanclient

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsfullsoftware"
)

func TestSoftwareHistoryConsentExplicitDefaultOffRotationAndLegacyIsolation(t *testing.T) {
	device, binding := "agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64)
	at := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	st := &fullSoftwareConsentMemory{files: map[string][]byte{}}
	marker := &fullSoftwareTestMarker{}
	exists := false
	open := func(create bool) (windowsfullsoftware.Storage, error) {
		if !exists {
			if !create {
				return nil, os.ErrNotExist
			}
			exists = true
		}
		return st, nil
	}
	configure := func(mode string, history bool) (WindowsFullSoftwareConsentResult, error) {
		return updateWindowsSoftwareConsent(device, binding, mode, history, open, func() time.Time { return at }, marker)
	}
	current := func() windowsfullsoftware.Consent {
		c, e := windowsfullsoftware.DecodeConsent(st.files["consent.json"])
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	for _, mode := range []string{"preview", "disable"} {
		r, e := configure(mode, true)
		if e != nil || r.Scope != windowsfullsoftware.HistoryScope || r.Enabled || exists || marker.used || st.writes != 0 {
			t.Fatal("history read created scope", mode, e)
		}
	}
	if _, e := configure("enable", true); e == nil || exists || marker.used || st.writes != 0 {
		t.Fatal("history alone granted ordinary software")
	}
	if _, e := configure("enable", false); e != nil {
		t.Fatal(e)
	}
	base := current()
	if base.HistoryScope != "" {
		t.Fatal("ordinary software granted history")
	}
	writes := st.writes
	if r, e := configure("preview", true); e != nil || r.Enabled || st.writes != writes {
		t.Fatal("preview changed consent", e)
	}
	at = at.Add(time.Second)
	if r, e := configure("enable", true); e != nil || !r.Enabled {
		t.Fatal("explicit history rejected", e)
	}
	first := current()
	if !first.Enabled || first.HistoryScope != windowsfullsoftware.HistoryScope || first.GrantID == base.GrantID || first.Revision != base.Revision+1 || first.ChangedAt != at {
		t.Fatal("history did not rotate parent authority")
	}
	writes = st.writes
	for _, history := range []bool{false, true} {
		if _, e := configure("enable", history); e != nil || st.writes != writes || current() != first {
			t.Fatal("idempotent enable changed existing authority")
		}
	}
	at = at.Add(time.Second)
	if r, e := configure("disable", true); e != nil || r.Enabled {
		t.Fatal("history disable rejected", e)
	}
	disabled := current()
	if !disabled.Enabled || disabled.HistoryScope != "" || disabled.GrantID == first.GrantID || disabled.Revision != first.Revision+1 {
		t.Fatal("history disable did not rotate and clear")
	}
	if _, e := configure("enable", false); e != nil || current() != disabled {
		t.Fatal("legacy enable restored disabled history")
	}
	at = at.Add(time.Second)
	if _, e := configure("enable", true); e != nil {
		t.Fatal(e)
	}
	second := current()
	if second.GrantID == first.GrantID || second.GrantID == disabled.GrantID || second.Revision != disabled.Revision+1 {
		t.Fatal("reenable reused baseline authority")
	}
	at = at.Add(time.Second)
	if _, e := configure("disable", false); e != nil {
		t.Fatal(e)
	}
	parentDisabled := current()
	if parentDisabled.Enabled || parentDisabled.HistoryScope != "" || parentDisabled.GrantID == second.GrantID {
		t.Fatal("ordinary disable retained active history")
	}
	if _, e := configure("enable", true); e == nil {
		t.Fatal("history enabled disabled software")
	}
	at = at.Add(time.Second)
	if _, e := configure("enable", false); e != nil {
		t.Fatal(e)
	}
	if current().HistoryScope != "" {
		t.Fatal("legacy reenable restored history")
	}
	before := bytes.Clone(st.files["consent.json"])
	at = base.ChangedAt.Add(-time.Second)
	if _, e := configure("enable", true); e == nil || !bytes.Equal(before, st.files["consent.json"]) {
		t.Fatal("history accepted backward clock")
	}
}

func TestSoftwareHistoryGrantRotationDiscardsOldSenderPackWithoutRecapture(t *testing.T) {
	for _, historyBefore := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable", true: "disable"}[historyBefore], func(t *testing.T) {
			device, binding := "agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64)
			at := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
			st := &fullSoftwareConsentMemory{files: map[string][]byte{}}
			if e := windowsfullsoftware.InitializeState(st, device, binding); e != nil {
				t.Fatal(e)
			}
			c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: binding, GrantID: strings.Repeat("3", 32), Revision: 1, Enabled: true, ChangedAt: at}
			if historyBefore {
				c.HistoryScope = windowsfullsoftware.HistoryScope
			}
			raw, e := windowsfullsoftware.EncodeConsent(c)
			if e != nil {
				t.Fatal(e)
			}
			st.Write("consent.json", raw)
			state, e := windowsfullsoftware.OpenState(st, device, binding)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = state.Reserve(c, at); e != nil {
				t.Fatal(e)
			}
			if e = state.Finish(windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: []windowsfullsoftware.Row{}}, nil, at); e != nil {
				t.Fatal(e)
			}
			raw, status, e := state.Next(c, at)
			if e != nil || status != "pending" || len(raw) == 0 {
				t.Fatal("missing frozen old pack", status, e)
			}
			oldPack := bytes.Clone(st.files["pack.json"])
			floor := state.Floor()
			state.Close()
			at = at.Add(time.Second)
			mode := "enable"
			if historyBefore {
				mode = "disable"
			}
			_, e = updateWindowsSoftwareConsent(device, binding, mode, true, func(bool) (windowsfullsoftware.Storage, error) { return st, nil }, func() time.Time { return at }, &fullSoftwareTestMarker{used: true})
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(oldPack, st.files["pack.json"]) {
				t.Fatal("consent rewrote old frozen pack")
			}
			next, e := windowsfullsoftware.DecodeConsent(st.files["consent.json"])
			if e != nil {
				t.Fatal(e)
			}
			state, e = windowsfullsoftware.OpenState(st, device, binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			if next == c || next.Revision != c.Revision+1 || next.GrantID == c.GrantID {
				t.Fatal("rotation missing")
			}
			raw, status, e = state.Next(next, at)
			if e != nil || status != "discarded_unconsented" || len(raw) != 0 || state.Floor() != floor || state.Pending() {
				t.Fatal("old pack sent or recaptured under new grant", status, e)
			}
			if _, status, e = state.Next(next, at); e != nil || status != "not_due" || state.Floor() != floor {
				t.Fatal("rotation reset capture floor", status, e)
			}
		})
	}
}

func TestSoftwareHistoryConsentUsedStateAndAcknowledgementFailClosed(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		for _, used := range []bool{false, true} {
			writes := 0
			_, e := updateWindowsSoftwareConsent("agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64), mode, true, func(create bool) (windowsfullsoftware.Storage, error) {
				if create {
					writes++
				}
				return nil, os.ErrNotExist
			}, time.Now, &fullSoftwareTestMarker{used: used})
			if writes != 0 || (used || mode == "enable") && e == nil {
				t.Fatal("history recreated lost/ungranted store", mode, used, e)
			}
		}
	}
	for _, tc := range []struct {
		mode string
		ack  bool
	}{{"enable", false}, {"preview", true}, {"disable", true}, {"unknown", false}} {
		if _, e := ConfigureWindowsSoftwareHistory("unused", tc.mode, tc.ack, false); e != ErrConfiguration {
			t.Fatal("bad acknowledgement reached state", tc, e)
		}
	}
}
