//go:build ignore

// Synthetic contract vectors only; no native registry read, grant or host action.
// go run web/scripts/windows-full-software-fixtures.go > web/src/windows-full-software-go-fixture.json
package main

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/windowsfullsoftware"
	"os"
	"strings"
	"time"
)

func main() {
	at := time.Date(2026, 10, 11, 6, 0, 0, 0, time.UTC)
	consent := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: at.Add(-time.Hour)}
	rows := make([]windowsfullsoftware.Row, 617)
	for i := range rows {
		name := fmt.Sprintf("Fixture Software %04d", i)
		version := fmt.Sprintf("%d.0", i)
		publisher := fmt.Sprintf("Synthetic Publisher %04d", i)
		view := "64"
		if i%2 == 0 {
			view = "32"
		}
		rows[i] = windowsfullsoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), RegistryView: view, Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	hostile := "<img src=x onerror=alert(1)> [.*] ÄÖÜ & 🛠"
	rows[616].Publisher = &hostile
	rows[615].Version = nil
	rows[615].VersionQuality = "unavailable"
	rows[615].Publisher = nil
	rows[615].PublisherQuality = "unavailable"
	values := []any{}
	for _, all := range [][]windowsfullsoftware.Row{rows, {}} {
		messages, err := windowsfullsoftware.Build("agent_"+strings.Repeat("a", 32), consent, 1, windowsfullsoftware.Capture{StartedAt: at, FinishedAt: at.Add(time.Second), Rows: all, Complete: true})
		if err != nil {
			panic(err)
		}
		m := messages[0]
		values = append(values, struct {
			Complete windowsfullsoftware.Complete `json:"complete"`
			Rows     []windowsfullsoftware.Row    `json:"rows"`
		}{windowsfullsoftware.Complete{Manifest: *m.Manifest, ManifestSHA256: m.ManifestSHA256, ReceivedAt: at.Add(2 * time.Second)}, all})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(values); err != nil {
		panic(err)
	}
}
