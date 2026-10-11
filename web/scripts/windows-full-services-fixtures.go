//go:build ignore

// Synthetic contract vectors only; no native API, grant or host action.
// go run web/scripts/windows-full-services-fixtures.go > web/src/windows-full-services-go-fixture.json
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"
    "localrmm/internal/windowsfullservices"
)
func main() {
    at := time.Date(2026, 10, 11, 6, 0, 0, 0, time.UTC)
    consent := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: at.Add(-time.Hour)}
    rows := make([]windowsfullservices.Row, 617)
    for i := range rows {
        name := fmt.Sprintf("FixtureService%04d", i)
        display := fmt.Sprintf("Synthetic Dienst %04d", i)
        state := "running"; if i%3 == 0 { state = "stopped" }
        pid := uint32(i)
        rows[i] = windowsfullservices.Row{Name:name, DisplayName:&display, DisplayNameQuality:"observed", State:&state, StateQuality:"observed", PID:&pid, PIDQuality:"observed"}
        if state == "stopped" { rows[i].PID = nil; rows[i].PIDQuality = "unavailable" }
    }
    hostile := "<img src=x onerror=alert(1)> [.*] ÄÖÜ & 🛠"
    rows[616].DisplayName = &hostile
    rows[615].DisplayName = nil; rows[615].DisplayNameQuality = "unavailable"
    rows[615].State = nil; rows[615].StateQuality = "unavailable"
    rows[615].PID = nil; rows[615].PIDQuality = "unavailable"
    values := []any{}
    for _, all := range [][]windowsfullservices.Row{rows, {}} {
        messages, err := windowsfullservices.Build("agent_"+strings.Repeat("a",32), consent, 1, windowsfullservices.Capture{StartedAt:at, FinishedAt:at.Add(time.Second), Rows:all, Complete:true})
        if err != nil { panic(err) }
        m := messages[0]
        values = append(values, struct { Complete windowsfullservices.Complete `json:"complete"`; Rows []windowsfullservices.Row `json:"rows"` }{windowsfullservices.Complete{Manifest:*m.Manifest, ManifestSHA256:m.ManifestSHA256, ReceivedAt:at.Add(2*time.Second)}, all})
    }
    enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); if err := enc.Encode(values); err != nil { panic(err) }
}
