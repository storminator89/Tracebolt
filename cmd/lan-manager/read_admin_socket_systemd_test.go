//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"localrmm/internal/systeminventory"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type readAdminSocketNativeResult struct {
	SchemaVersion    string `json:"schemaVersion"`
	Operation        string `json:"operation"`
	GrantEpoch       string `json:"grantEpoch"`
	PolicyDigest     string `json:"policyDigest"`
	AgentPID         int    `json:"agentPID"`
	HelperPID        int    `json:"helperPID"`
	AgentUID         int    `json:"agentUID"`
	AgentGID         int    `json:"agentGID"`
	HelperUID        int    `json:"helperUID"`
	HelperGID        int    `json:"helperGID"`
	Revoked          bool   `json:"revoked"`
	CleanupConfirmed bool   `json:"cleanupConfirmed"`
	FloorPreserved   bool   `json:"floorPreserved"`
	PendingChecked   bool   `json:"pendingChecked"`
}

func readAdminNativeMaintenance(t *testing.T, c *readAdminNativeCommand, operation string, result *readAdminSocketNativeResult) bool {
	t.Helper()
	path, ok := c.maintenance[operation]
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.python, "-I", "-c", readAdminLauncher, path)
	cmd.Env = c.environment()
	raw, err := readAdminCaptureLifecycle(cmd)
	defer clear(raw)
	valid := false
	defer func() {
		if !valid {
			readAdminLogLifecycleFailure(t, operation, readAdminParseMaintenanceFailure(raw))
		}
	}()
	remember := readAdminRememberMaintenanceFailure(operation, t.Failed(), c.options.setupDiagnostic())
	if len(raw) <= 4096 && err != nil && remember {
		var failure struct {
			SchemaVersion string `json:"schemaVersion"`
			FailureStage  string `json:"failureStage"`
		}
		if json.Unmarshal(raw, &failure) == nil && failure.SchemaVersion == "tracebolt.read-admin-result.v2" {
			c.options.setupFailure = readAdminSetupFailure(failure.FailureStage)
		} else {
			c.options.setupFailure = "maintenance-operation-failed"
		}
	}
	if len(raw) > 4096 && remember {
		c.options.setupFailure = "driver-output-invalid"
	}
	if err != nil || len(raw) > 4096 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	valid = decoder.Decode(result) == nil && result.SchemaVersion == "tracebolt.read-admin-socket-native.v1" && result.Operation == operation
	if !valid && remember {
		c.options.setupFailure = "maintenance-operation-failed"
	}
	return valid
}

// Cleanup must not replace the primary failure of an already failed test.
func readAdminRememberMaintenanceFailure(operation string, failed bool, setup string) bool {
	return operation != "cleanup" || !failed && (setup == "none" || setup == "not_attempted")
}

// Pure parser: ordinary tests supply invented status/cgroup strings only.
func readAdminSocketProcessMatches(status, cgroup string, uid, gid int, capability uint64, unit string) bool {
	if uid <= 0 || gid <= 0 || strings.TrimSpace(cgroup) != "0::/system.slice/"+unit {
		return false
	}
	fields := map[string][]string{}
	for _, line := range strings.Split(status, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, exists := fields[name]; exists {
			return false
		}
		fields[name] = strings.Fields(value)
	}
	for name, id := range map[string]int{"Uid": uid, "Gid": gid} {
		values := fields[name]
		if len(values) != 4 {
			return false
		}
		for _, value := range values {
			if value != strconv.Itoa(id) {
				return false
			}
		}
	}
	groups, exists := fields["Groups"]
	if !exists || !(len(groups) == 0 || len(groups) == 1 && groups[0] == strconv.Itoa(gid)) {
		return false
	}
	for _, name := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"} {
		values := fields[name]
		if len(values) != 1 {
			return false
		}
		value, err := strconv.ParseUint(values[0], 16, 64)
		if err != nil || value != capability {
			return false
		}
	}
	return reflect.DeepEqual(fields["NoNewPrivs"], []string{"1"}) && reflect.DeepEqual(fields["Seccomp"], []string{"2"})
}

func readAdminCheckSocketProcess(t *testing.T, pid, uid, gid int, capability uint64, unit, binary string) {
	t.Helper()
	if pid <= 0 {
		t.Fatal("native process absent")
	}
	prefix := "/proc/" + strconv.Itoa(pid)
	status, err := os.ReadFile(prefix + "/status")
	if err != nil || len(status) > 65536 {
		t.Fatal("native process status unavailable")
	}
	cgroup, err := os.ReadFile(prefix + "/cgroup")
	if err != nil || len(cgroup) > 4096 || !readAdminSocketProcessMatches(string(status), string(cgroup), uid, gid, capability, unit) {
		t.Fatal("actual process capability/identity/cgroup contract")
	}
	installed, err := os.Stat(binary)
	if err != nil {
		t.Fatal("installed executable unavailable")
	}
	actual, err := os.Stat(prefix + "/exe")
	if err != nil || !os.SameFile(installed, actual) {
		t.Fatal("running executable differs from installed artifact")
	}
	for _, name := range []string{"pid", "net", "user"} {
		first, err := os.Stat("/proc/1/ns/" + name)
		if err != nil {
			t.Fatal("PID1 namespace unavailable")
		}
		current, err := os.Stat(prefix + "/ns/" + name)
		if err != nil || !os.SameFile(first, current) {
			t.Fatal("native process outside PID1-local namespace")
		}
	}
	// Typed nsfs, pidfd and listener/sockfs checks are exercised transitively by
	// successful production capture; this sampled check is not a race proof.
}

func readAdminFixtureOwner(rows []systeminventory.Socket, protocol string, port uint16, pid uint32, process string) bool {
	for _, row := range rows {
		if row.Protocol != protocol || row.Local.Address != "127.0.0.1" || row.Local.Port != port || row.Attribution.Coverage != systeminventory.AttributionObserved {
			continue
		}
		for _, owner := range row.Owners {
			if owner.PID == pid && owner.ProcessName != nil && *owner.ProcessName == process {
				return true
			}
		}
	}
	return false
}

func readAdminSocketOwnersAndRevoke(t *testing.T, c *readAdminNativeCommand, get func(string, any), query func(string, any, any), stage *string, uid, gid int, bindOperatorTest func(*testing.T) func()) {
	t.Helper()
	*stage = "read_admin_socket_owners"
	// The ordinary installed service must attribute a DIFFERENT root principal.
	// No manual same-UID helper client or out-of-cgroup collector substitutes.
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("bounded TCP fixture unavailable")
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("bounded UDP fixture unavailable")
	}
	defer udp.Close()
	ports := map[string]uint16{"tcp": uint16(tcp.Addr().(*net.TCPAddr).Port), "udp": uint16(udp.LocalAddr().(*net.UDPAddr).Port)}
	process, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal("fixture process identity unavailable")
	}
	var devices struct{ Items []model.Device }
	get("/api/devices", &devices)
	if len(devices.Items) != 1 {
		t.Fatal("fresh device identity unavailable")
	}
	device := devices.Items[0].ID
	var matched enrollmentstore.SystemView
	until := time.Now().Add(150 * time.Second)
	for time.Now().Before(until) {
		var view enrollmentstore.SystemView
		get("/api/devices/"+device+"/inventory/system", &view)
		if view.Latest == nil || view.Latest.SocketOwnerProvenance == nil || view.Sequence == nil || view.LastComplete.Sockets == nil || view.LastComplete.Sockets.Sequence != *view.Sequence || view.Latest.Sockets.Coverage != systeminventory.Complete {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		p := view.Latest.SocketOwnerProvenance
		if systeminventory.ValidateSocketOwnerProvenance(*p, view.Latest.CollectedAt, view.Latest.DurationMS) != nil || view.Status != "fresh" {
			t.Fatal("received socket provenance invalid")
		}
		found := true
		for protocol, port := range ports {
			request := enrollmentstore.SystemPageRequest{Section: "sockets", GenerationID: view.Latest.GenerationID, Search: strconv.Itoa(int(port)), Limit: 100}
			yes := false
			for pages := 0; pages < 164; pages++ {
				var page enrollmentstore.SystemPageResult
				query("/api/devices/"+device+"/inventory/system/query", request, &page)
				if page.GenerationID != view.Latest.GenerationID || !reflect.DeepEqual(page.SocketOwnerProvenance, p) {
					t.Fatal("socket page/provenance generation changed")
				}
				yes = yes || readAdminFixtureOwner(page.Sockets, protocol, port, uint32(os.Getpid()), strings.TrimSpace(string(process)))
				if yes || page.Exhausted {
					break
				}
				if page.NextCursor == "" || page.NextCursor == request.Cursor {
					t.Fatal("socket page did not advance")
				}
				request.Cursor = page.NextCursor
			}
			found = found && yes
		}
		if found {
			matched = view
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	failureStage := ""
	defer func() {
		if failureStage != "" {
			*stage = failureStage
		}
	}()
	var native readAdminSocketNativeResult
	if matched.Sequence == nil {
		// Ownership is still required for PASS and for grant-bound revocation.
		// Its absence does not invalidate the separately proven installation.
		t.Error("actual installed-service fixture owners not observed")
		failureStage = *stage
	} else {
		if !readAdminNativeMaintenance(t, c, "inspect-socket", &native) || native.GrantEpoch != matched.Latest.SocketOwnerProvenance.GrantEpoch || native.PolicyDigest != matched.Latest.SocketOwnerProvenance.PolicyDigest {
			t.Fatal("received helper source not bound to installed grant")
		}
		readAdminCheckSocketProcess(t, native.AgentPID, native.AgentUID, native.AgentGID, 0, "tracebolt-agent.service", "/opt/tracebolt-agent/lan-agent")
		readAdminCheckSocketProcess(t, native.HelperPID, native.HelperUID, native.HelperGID, 1<<19, "tracebolt-socket-owner-reader.service", "/opt/tracebolt-agent/socket-owner-reader")
		c.options.checks.InstalledServiceOwners = true
		c.options.checks.V4Provenance = true
	}
	// Each independent check retains its own assertions and can fail without
	// suppressing the other. Operator errors belong to the active child too.
	run := func(name string, check func(*testing.T)) {
		*stage = name
		if !t.Run(name, func(child *testing.T) {
			restore := bindOperatorTest(child)
			defer restore()
			check(child)
		}) && failureStage == "" {
			failureStage = name
		}
	}
	if c.options.scenario == "complete" {
		run("read_admin_journal_content", func(t *testing.T) {
			readAdminJournalContent(t, c, device, get, query)
			c.options.checks.JournalContent = true
		})
	}
	var restartedSequence uint64
	run("read_admin_restart", func(t *testing.T) {
		installer := filepath.Join(filepath.Dir(c.configs[false]), "tracebolt-"+readAdminFixtureVersion+"-linux-amd64-agent-service")
		args := []string{"--action", "restart"}
		if c.options.profile == lanconfig.HTTPTest {
			args = append(args, "--insecure-http-test")
		}
		// The production read-only preflight verifies loaded unit ownership,
		// retained identity and manifest-bound artifact hashes independently of
		// socket attribution. Apply repeats those checks before service changes.
		cmd := exec.Command(installer, args...)
		cmd.Env = systemdCleanEnvironment()
		if readAdminRunLifecycle(t, cmd, "restart_preflight") != nil {
			t.Fatal("owned native agent restart preflight failed")
		}
		systemdCheckProcessIdentity(t, uid, gid)
		var before enrollmentstore.SystemView
		get("/api/devices/"+device+"/inventory/system", &before)
		if before.Sequence == nil || before.Latest == nil || before.Latest.GenerationID == "" || before.Status != "fresh" {
			t.Fatal("ordinary restart baseline unavailable")
		}
		cmd = exec.Command(installer, append(args, "--apply")...)
		cmd.Env = systemdCleanEnvironment()
		if readAdminRunLifecycle(t, cmd, "restart_apply") != nil {
			t.Fatal("owned native agent restart failed")
		}
		restartedSequence = readAdminWaitRestartSystem(t, device, before, time.Now().UTC(), native.GrantEpoch, get)
		systemdCheckProcessIdentity(t, uid, gid)
		c.options.checks.ServiceRestartOnline = true
	})
	if failureStage != "" {
		// Preserve the first stage and prevent the caller marking completion.
		// In particular, no grant-dependent revoke runs without owner proof.
		t.FailNow()
	}
	*stage = "read_admin_revoke"
	before := readAdminIdentitySnapshot(t)
	authority := readAdminAuthoritySnapshot(t)
	var revoked readAdminSocketNativeResult
	if !readAdminNativeMaintenance(t, c, "revoke-socket", &revoked) {
		t.Fatal("native revoke verification failed")
	}
	if !reflect.DeepEqual(before, readAdminIdentitySnapshot(t)) || !reflect.DeepEqual(authority, readAdminAuthoritySnapshot(t)) {
		t.Fatal("socket revoke changed identity or journal/inventory authority")
	}
	if !revoked.Revoked || !revoked.FloorPreserved || !revoked.PendingChecked {
		readAdminLogLifecycleFailure(t, "revoke-socket", readAdminLifecycleDiagnostic{"maintenance-operation-failed", "unavailable", "unavailable", "unavailable"})
		t.Fatal("revoke private floor/pending/tombstone contract unconfirmed")
	}
	c.options.checks.RevocationCompleted = true
	*stage = "read_admin_post_revoke"
	_ = readAdminWaitOrdinarySystem(t, device, restartedSequence, time.Now().UTC(), get)
	c.options.checks.RevokedNoAuthority = true

}

// Pure report predicate: neither a retained generation nor receipt time alone
// proves a new ordinary collection after the completed restart.
func readAdminRestartObservationAdvanced(view, before enrollmentstore.SystemView, after time.Time) bool {
	return before.Sequence != nil && before.Latest != nil && before.Latest.GenerationID != "" &&
		view.Sequence != nil && *view.Sequence > *before.Sequence && view.Latest != nil &&
		view.Latest.GenerationID != "" && view.Latest.GenerationID != before.Latest.GenerationID &&
		view.Latest.CollectedAt.After(before.Latest.CollectedAt) && view.Latest.CollectedAt.After(after) && view.Status == "fresh"
}

func readAdminWaitRestartSystem(t *testing.T, device string, before enrollmentstore.SystemView, after time.Time, epoch string, get func(string, any)) uint64 {
	t.Helper()
	until := time.Now().Add(120 * time.Second)
	for time.Now().Before(until) {
		var view enrollmentstore.SystemView
		get("/api/devices/"+device+"/inventory/system", &view)
		if readAdminRestartObservationAdvanced(view, before, after) {
			p := view.Latest.SocketOwnerProvenance
			if epoch == "" || p != nil && p.GrantEpoch == epoch && systeminventory.ValidateSocketOwnerProvenance(*p, view.Latest.CollectedAt, view.Latest.DurationMS) == nil {
				return *view.Sequence
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	if epoch == "" {
		t.Fatal("new ordinary online report not observed after revoke/restart")
	}
	t.Fatal("restarted installed service did not return online with socket provenance")
	return 0
}

func readAdminWaitOrdinarySystem(t *testing.T, device string, afterSequence uint64, after time.Time, get func(string, any)) uint64 {
	t.Helper()
	until := time.Now().Add(120 * time.Second)
	for time.Now().Before(until) {
		var view enrollmentstore.SystemView
		get("/api/devices/"+device+"/inventory/system", &view)
		if view.Sequence != nil && *view.Sequence > afterSequence && view.Latest != nil && view.Latest.CollectedAt.After(after) && view.Status == "fresh" {
			if view.Latest.SocketOwnerProvenance != nil {
				t.Fatal("new helper authority reported after revocation")
			}
			// Retained last-complete metadata need not be erased by scope revocation.
			return *view.Sequence
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("new ordinary online report not observed after revoke/restart")
	return 0
}

func readAdminJournalContent(t *testing.T, c *readAdminNativeCommand, device string, get func(string, any), query func(string, any, any)) {
	t.Helper()
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("journal fixture entropy unavailable")
	}
	unit := fmt.Sprintf("tracebolt-read-admin-journal-%x.service", nonce)
	marker := fmt.Sprintf("tracebolt acceptance fixture %x", nonce)
	started := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	args := []string{"--unit=" + unit, "--property=Type=oneshot", "--property=RemainAfterExit=yes", "--property=StandardOutput=journal", "--property=StandardError=journal", "--", "/usr/bin/printf", "%s\n", marker}
	cmd := exec.Command("/usr/bin/systemd-run", args...)
	cmd.Env = systemdCleanEnvironment()
	if err := cmd.Run(); err != nil {
		t.Fatal("fresh bounded journal fixture creation failed")
	}
	// Create-only systemd-run succeeded for an unpredictable name. Capture and
	// retain its immutable invocation identity before registering narrow cleanup.
	unitState := func() map[string]string {
		cmd := exec.Command("/usr/bin/systemctl", "show", unit, "--property=Names,Transient,ActiveState,SubState,InvocationID,Result", "--all", "--no-pager")
		cmd.Env = systemdCleanEnvironment()
		raw, err := cmd.Output()
		if err != nil || len(raw) > 4096 {
			t.Fatal("owned fixture state unavailable")
		}
		out := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatal("fixture state invalid")
			}
			out[k] = v
		}
		return out
	}
	var invocation string
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		state := unitState()
		if state["Names"] != unit || state["Transient"] != "yes" {
			t.Fatal("journal fixture ownership changed")
		}
		if state["ActiveState"] == "active" && state["SubState"] == "exited" && state["Result"] == "success" && len(state["InvocationID"]) == 32 {
			invocation = state["InvocationID"]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if invocation == "" {
		t.Fatal("journal fixture did not complete")
	}
	t.Cleanup(func() {
		state := unitState()
		if state["Names"] != unit || state["Transient"] != "yes" || state["InvocationID"] != invocation {
			t.Error("journal fixture cleanup ownership changed")
			return
		}
		cmd := exec.Command("/usr/bin/systemctl", "stop", unit)
		cmd.Env = systemdCleanEnvironment()
		if cmd.Run() != nil {
			t.Error("owned fixture stop failed")
		}
	})
	type contentView struct {
		ExpectedFloor string
		Request       *journalrequest.Status
	}
	var view contentView
	get("/api/devices/"+device+"/journal", &view)
	q := journalview.Query{Unit: unit, Start: started, End: time.Now().UTC().Truncate(time.Microsecond), MaxPriority: 7}
	query("/api/devices/"+device+"/journal/create", map[string]any{"expectedFloor": view.ExpectedFloor, "expectedPolicyGeneration": readAdminExpectedGeneration(t), "query": q, "acknowledgeLogContent": true, "acknowledgePlaintext": c.options.profile == lanconfig.HTTPTest}, &view)
	until = time.Now().Add(120 * time.Second)
	for time.Now().Before(until) {
		get("/api/devices/"+device+"/journal", &view)
		if view.Request != nil && view.Request.Receipt != nil {
			var page journalcache.Page
			query("/api/devices/"+device+"/journal/query", map[string]any{"identity": view.Request.Description.Identity, "snapshotDigest": view.Request.Receipt.ResultDigest, "search": marker, "offset": 0, "limit": 100}, &page)
			matched := false
			for i := range page.Rows {
				row := page.Rows[i]
				matched = matched || row.Unit == unit && row.Message == marker && !row.Timestamp.Before(q.Start) && !row.Timestamp.After(q.End)
				page.Rows[i].Message = ""
			}
			if page.SchemaVersion != "tracebolt.journal-page.v1" || page.DeviceID != device || page.Identity != view.Request.Description.Identity || page.SnapshotDigest != view.Request.Receipt.ResultDigest || page.Query != q || !matched {
				t.Fatal("actual journal fixture content not returned for exact request")
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("actual bounded journal content request did not complete")
}

func TestReadAdminSocketProcessMatches(t *testing.T) {
	status := "Uid:\t1201 1201 1201 1201\nGid:\t1202 1202 1202 1202\nGroups:\t\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	for _, field := range []string{"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"} {
		status += field + ":\t0000000000080000\n"
	}
	cgroup := "0::/system.slice/tracebolt-socket-owner-reader.service\n"
	for _, groups := range []string{"", "1202"} {
		sample := strings.Replace(status, "Groups:\t\n", "Groups:\t"+groups+"\n", 1)
		if !readAdminSocketProcessMatches(sample, cgroup, 1201, 1202, 1<<19, "tracebolt-socket-owner-reader.service") {
			t.Fatal("primary-only fixture rejected")
		}
	}
	for _, change := range [][2]string{{"Groups:\t\n", "Groups:\t1202 1202\n"}, {"Groups:\t\n", "Groups:\t999\n"}, {"CapAmb:\t0000000000080000", "CapAmb:\t0000000000000000"}, {"NoNewPrivs:\t1", "NoNewPrivs:\t0"}, {"Seccomp:\t2", "Seccomp:\t0"}, {"1201 1201 1201 1201", "1201 0 1201 1201"}} {
		if readAdminSocketProcessMatches(strings.Replace(status, change[0], change[1], 1), cgroup, 1201, 1202, 1<<19, "tracebolt-socket-owner-reader.service") {
			t.Fatal("incorrect native process fixture accepted")
		}
	}
	if readAdminSocketProcessMatches(status, "0::/user.slice/session.scope\n", 1201, 1202, 1<<19, "tracebolt-socket-owner-reader.service") {
		t.Fatal("out-of-cgroup fixture accepted")
	}
}

func TestReadAdminFixtureOwner(t *testing.T) {
	name := "fixture"
	row := systeminventory.Socket{Protocol: "tcp", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: 4321}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionObserved}, Owners: []systeminventory.Owner{{PID: 2345, ProcessName: &name}}}
	if !readAdminFixtureOwner([]systeminventory.Socket{row}, "tcp", 4321, 2345, name) {
		t.Fatal("controlled owner rejected")
	}
	for _, wrong := range []uint32{0, 2346} {
		if readAdminFixtureOwner([]systeminventory.Socket{row}, "tcp", 4321, wrong, name) {
			t.Fatal("wrong fixture owner accepted")
		}
	}
	row.Attribution.Coverage = systeminventory.AttributionPartial
	if readAdminFixtureOwner([]systeminventory.Socket{row}, "tcp", 4321, 2345, name) {
		t.Fatal("partial fixture passed native ownership")
	}
}

func TestReadAdminMaintenanceFailurePreservesPrimary(t *testing.T) {
	for _, tc := range []struct {
		operation, setup string
		failed, remember bool
	}{
		{"cleanup", "none", false, true},
		{"cleanup", "not_attempted", false, true},
		{"cleanup", "none", true, false},
		{"cleanup", "not_attempted", true, false},
		{"cleanup", "loaded-unit-ownership", false, false},
		{"cleanup", "loaded-unit-ownership", true, false},
		{"inspect-socket", "none", false, true},
		{"revoke-socket", "none", true, true},
	} {
		if readAdminRememberMaintenanceFailure(tc.operation, tc.failed, tc.setup) != tc.remember {
			t.Fatal("maintenance replaced primary diagnostic or lost its own failure")
		}
	}
}

func TestReadAdminRestartRequiresNewOrdinaryGeneration(t *testing.T) {
	sequence := uint64(4)
	before := enrollmentstore.SystemView{Sequence: &sequence, Status: "fresh", Latest: &enrollmentstore.SystemSnapshotSummary{GenerationID: "before", CollectedAt: time.Unix(1000, 0)}}
	after := time.Unix(1001, 0)
	newView := func() enrollmentstore.SystemView {
		next := sequence + 1
		return enrollmentstore.SystemView{Sequence: &next, Status: "fresh", Latest: &enrollmentstore.SystemSnapshotSummary{GenerationID: "after", CollectedAt: time.Unix(1002, 0)}}
	}
	if !readAdminRestartObservationAdvanced(newView(), before, after) {
		t.Fatal("fresh ordinary report without socket provenance rejected")
	}
	for _, mutate := range []func(*enrollmentstore.SystemView){
		func(v *enrollmentstore.SystemView) { v.Sequence = nil },
		func(v *enrollmentstore.SystemView) { v.Sequence = before.Sequence },
		func(v *enrollmentstore.SystemView) { v.Latest = nil },
		func(v *enrollmentstore.SystemView) { v.Latest.GenerationID = "" },
		func(v *enrollmentstore.SystemView) { v.Latest.GenerationID = before.Latest.GenerationID },
		func(v *enrollmentstore.SystemView) { v.Latest.CollectedAt = after },
		func(v *enrollmentstore.SystemView) { v.Latest.CollectedAt = before.Latest.CollectedAt },
		func(v *enrollmentstore.SystemView) { v.Status = "stale" },
	} {
		view := newView()
		mutate(&view)
		if readAdminRestartObservationAdvanced(view, before, after) {
			t.Fatal("retained or stale restart report accepted")
		}
	}
	for _, prior := range []enrollmentstore.SystemView{{}, {Sequence: &sequence}, {Sequence: &sequence, Latest: &enrollmentstore.SystemSnapshotSummary{}}} {
		if readAdminRestartObservationAdvanced(newView(), prior, after) {
			t.Fatal("missing restart baseline accepted")
		}
	}
}
