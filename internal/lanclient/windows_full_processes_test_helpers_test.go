//go:build linux

package lanclient

import (
	"bytes"
	"fmt"
	"localrmm/internal/windowsfullprocesses"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type fullProcessesMemory struct{ files map[string][]byte }

func (s *fullProcessesMemory) Read(n string) ([]byte, error) {
	raw, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(raw), nil
}
func (s *fullProcessesMemory) Write(n string, b []byte) error {
	s.files[n] = bytes.Clone(b)
	return nil
}
func (s *fullProcessesMemory) Close() error { return nil }

type fullProcessesRoundTrip func(*http.Request) (*http.Response, error)

func (f fullProcessesRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func inventedFullProcesses(n int) []windowsfullprocesses.Row {
	rows := make([]windowsfullprocesses.Row, n)
	for i := range rows {
		name := fmt.Sprintf("Process%05d.exe", i)
		rows[i] = windowsfullprocesses.Row{PID: uint32(i), ParentPID: 0, Name: &name, NameQuality: "observed", Threads: 1}
	}
	return rows
}
func fullProcessesLocal(t *testing.T, m Material) *fullProcessesMemory {
	t.Helper()
	st := &fullProcessesMemory{files: map[string][]byte{}}
	c := windowsfullprocesses.Consent{SchemaVersion: windowsfullprocesses.ConsentVersion, Scope: windowsfullprocesses.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC()}
	if e := windowsfullprocesses.InitializeState(st, m.config.AgentID, m.binding); e != nil {
		t.Fatal(e)
	}
	raw, e := windowsfullprocesses.EncodeConsent(c)
	if e != nil {
		t.Fatal(e)
	}
	st.Write("consent.json", raw)
	return st
}
