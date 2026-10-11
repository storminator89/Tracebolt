//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"fmt"
	"localrmm/internal/windowsnetworkcontext"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type networkContextMemory struct{ files map[string][]byte }

func (s *networkContextMemory) Read(n string) ([]byte, error) {
	raw, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s *networkContextMemory) Write(n string, b []byte) error {
	s.files[n] = bytes.Clone(b)
	return nil
}
func (s *networkContextMemory) Close() error { return nil }

type networkContextRoundTrip func(*http.Request) (*http.Response, error)

func (f networkContextRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func inventedNetworkContext(n int) []windowsnetworkcontext.Row {
	rows := make([]windowsnetworkcontext.Row, n)
	for i := range rows {
		rows[i] = windowsnetworkcontext.Row{ID: uint32(i + 1), Kind: "route", InterfaceIndex: 1, Route: &windowsnetworkcontext.Route{Destination: fmt.Sprintf("10.%d.%d.0/24", (i>>8)&255, i&255), NextHop: "10.0.0.1", Metric: 1, Protocol: 3, Origin: 0}}
	}
	return rows
}

func networkContextLocal(t *testing.T, m Material) *networkContextMemory {
	t.Helper()
	st := &networkContextMemory{files: map[string][]byte{}}
	c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
	if e := windowsnetworkcontext.InitializeState(st, m.config.AgentID, m.binding); e != nil {
		t.Fatal(e)
	}
	raw, e := windowsnetworkcontext.EncodeConsent(c)
	if e != nil {
		t.Fatal(e)
	}
	st.Write("consent.json", raw)
	return st
}

func newNetworkContextFixtureSender(m Material, st windowsnetworkcontext.Storage, now func() time.Time, collect func(context.Context) (windowsnetworkcontext.Capture, error)) (*networkContextSender, error) {
	return newNetworkContextSenderWithAuthority(m, st, now, collect, m.valid)
}
