//go:build linux

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packageupdatestore"
)

func TestPackageUpdateSQLiteSimulationThroughAuthenticatedAPI(t *testing.T) {
	ctx := context.Background()
	o := packageOperatorFixture(t, operatorauth.PlanUpdates, operatorauth.ExecuteUpdates)
	h := o.server.Config.Handler.(*operatorHandler)
	raw, e := os.ReadFile("../packageplan/testdata/plan.json")
	if e != nil {
		t.Fatal(e)
	}
	p, e := packageplan.Decode(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	b := packageupdate.Binding{ManagerID: "manager_11111111111111111111111111111111", DeviceID: namedDeviceID, IncarnationDigest: p.IncarnationDigest, RootPolicyDigest: p.RootPolicyDigest, TransportProfile: "production-tls"}
	dir := filepath.Join(t.TempDir(), "private")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := packageupdatestore.Create(ctx, filepath.Join(dir, "updates.db"), b, time.Now().UTC().Unix())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	f := packageupdate.SimulationFixture{EvidenceMode: "synthetic", Plan: p, Sources: []packageupdate.Source{{IdentityDigest: p.Packages[0].Archive.SourceIdentityDigest, Label: "Synthetic fixture repository", Suite: "trixie", Component: "main"}}, Outcome: "success", RebootState: "required"}
	h.packageUpdatesManager, e = packageupdate.NewSimulation(ctx, s, b, f, func() time.Time { return time.Now().UTC() })
	if e != nil {
		t.Fatal(e)
	}
	csrf := packageLogin(t, o)
	base := "/api/devices/" + namedDeviceID + "/package-updates"
	req := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	response, v := o.call(t, "POST", base+"/prepare", req, csrf, nil)
	if response.StatusCode != 200 || v["executionMode"] != "simulation" || v["available"] != false {
		t.Fatal("prepare contract", response.StatusCode, v)
	}
	preview := v["preview"].(map[string]any)
	digest := preview["digest"].(string)
	if preview["actorId"] != namedActorID || preview["items"].([]any)[0].(map[string]any)["sourceLabel"] != "Synthetic fixture repository" {
		t.Fatal("preview binding", preview)
	}
	approve := packageupdate.ApprovalRequest{RequestID: req.RequestID, PreviewDigest: digest}
	response, v = o.call(t, "POST", base+"/approve", approve, csrf, nil)
	if response.StatusCode != 200 || v["job"].(map[string]any)["state"] != packageupdate.Approved {
		t.Fatal("approval", response.StatusCode, v)
	}
	// Fixture dispatcher is deliberately outside HTTP and is never runtime-wired.
	if e = h.packageUpdatesManager.(*packageupdate.Manager).StartPendingSimulation(ctx, b.DeviceID); e != nil {
		t.Fatal(e)
	}
	exact := base + "/jobs/" + req.RequestID
	response, v = o.call(t, "GET", exact, nil, "", nil)
	if response.StatusCode != 200 || v["job"].(map[string]any)["state"] != packageupdate.Verifying {
		t.Fatal("progress", response.StatusCode, v)
	}
	response, v = o.call(t, "GET", exact, nil, "", nil)
	if response.StatusCode != 200 || v["job"].(map[string]any)["state"] != packageupdate.Succeeded || v["preview"].(map[string]any)["digest"] != digest {
		t.Fatal("saved verification", response.StatusCode, v)
	}
	result := v["job"].(map[string]any)["result"].(map[string]any)
	if result["reboot"].(map[string]any)["state"] != "required" || result["reboot"].(map[string]any)["source"] != "simulation" {
		t.Fatal("reboot evidence fabricated", result)
	}
	response, v = o.call(t, "POST", base+"/approve", approve, csrf, nil)
	if response.StatusCode != 200 || v["job"].(map[string]any)["state"] != packageupdate.Succeeded {
		t.Fatal("retry launched new job", response.StatusCode, v)
	}
	if response, _ = o.call(t, "GET", base+"/jobs/update_22222222222222222222222222222222", nil, "", nil); response.StatusCode != 404 {
		t.Fatal("unknown ID invented state", response.StatusCode)
	}
	if response, _ = o.call(t, "POST", exact, map[string]any{}, csrf, nil); response.StatusCode != 405 {
		t.Fatal("status route mutation", response.StatusCode)
	}
}
