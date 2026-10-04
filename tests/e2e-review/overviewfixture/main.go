// Disposable, loopback-only fixture for real operator complete-overview APIs.
// Every device observation and catalog is invented. No collector/package command
// is run. Stdin controls synthetic state; it is never an HTTP test backdoor.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/argon2"
	"localrmm/internal/api"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"localrmm/internal/store"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

const fixturePassword = "TRACEBOLT_OVERVIEW_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD"

var phase = "setup"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func id(prefix string) string {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	must(e)
	return prefix + hex.EncodeToString(b)
}
func jsonBytes(v any) []byte { b, e := json.Marshal(v); must(e); return b }
func ptr[T any](v T) *T      { return &v }

type fixture struct {
	service *enrollmentservice.Service
	store   *enrollmentstore.Store
	offset  atomic.Int64
	devices map[string]enrollmentstate.Snapshot
	seq     map[string]uint64
}

func (f *fixture) now() time.Time { return time.Now().UTC().Add(time.Duration(f.offset.Load())) }
func (f *fixture) seed(active bool) enrollmentstate.Snapshot {
	ctx := context.Background()
	created, e := f.service.CreateInvitation(ctx, id("request_"), "linux")
	must(e)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	defer clear(key)
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Invented browser fixture"}}, key)
	must(e)
	claimID := id("claim_")
	c, e := f.service.Challenge("127.0.0.1", created.Snapshot().InvitationID, claimID, "claim")
	must(e)
	request := id("request_")
	message, e := enrollmentcrypto.ClaimSigningMessage(c.Context, request, csr, created.Secret(), f.now())
	must(e)
	common := func(c enrollmentservice.Challenge) map[string]string {
		return map[string]string{"managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "challenge": c.Context.Challenge}
	}
	body := common(c)
	body["schemaVersion"] = enrollmentcrypto.ClaimVersion
	body["requestId"] = request
	body["invitationSecret"] = created.Secret()
	body["csr"] = base64.RawStdEncoding.EncodeToString(csr)
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	raw := jsonBytes(body)
	s, e := f.service.Claim(ctx, c.Context.Challenge, raw)
	clear(raw)
	delete(body, "invitationSecret")
	must(e)
	s, e = f.service.Approve(ctx, s.InvitationID, id("request_"), s.Claim.KeyFingerprint, s.Revision)
	must(e)
	if !active {
		return s
	}
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "status")
	must(e)
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	must(e)
	fp := sha256.Sum256(der)
	request = id("request_")
	message, e = enrollmentcrypto.StatusSigningMessage(c.Context, "status", request, der, f.now())
	must(e)
	body = common(c)
	body["schemaVersion"] = enrollmentcrypto.StatusVersion
	body["purpose"] = "status"
	body["requestId"] = request
	body["keyFingerprint"] = hex.EncodeToString(fp[:])
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	s, e = f.service.Status(ctx, c.Context.Challenge, jsonBytes(body))
	must(e)
	cert, e := f.store.CertificateForVerification(ctx, s.InvitationID)
	must(e)
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "activation")
	must(e)
	request = id("request_")
	message, e = enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), request, cert.CertificateHash(), f.now())
	must(e)
	body = map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))}
	s, e = f.service.Activate(ctx, c.Context.Challenge, jsonBytes(body))
	must(e)
	return s
}

// Every row here is invented. No collector or OS observation is invoked.
func processSnapshot(which, mode string, at time.Time) completeoverview.Snapshot {
	snapshot := completeoverview.Empty(id("sample_"), at.Add(-750*time.Millisecond), completeoverview.ReasonNotCollected)
	snapshot.CaptureFinishedAt = at.Add(-250 * time.Millisecond)
	n := 205
	if mode == "empty" {
		n = 0
	}
	rows := make([]completeoverview.Process, n)
	counts := completeoverview.FieldCoverage{}
	for i := range rows {
		name := fmt.Sprintf("Synthetic %s process %03d", which, i+1)
		if i == 0 || i == 100 || i == 200 {
			name += " Needle[.*]"
		}
		if mode == "replace" {
			name += " new"
		}
		rows[i] = completeoverview.Process{PID: uint32(i + 1), ParentPID: ptr(uint32(0)), Name: ptr(name), State: ptr("sleeping"), RSSBytes: ptr(uint64(i * 4096)), CPUTimeSeconds: ptr(float64(i) / 4), Threads: ptr(uint32(1)), Observation: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}}
		switch i {
		case 1:
			rows[i] = completeoverview.Process{PID: 2, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}
			counts.Denied++
		case 2:
			rows[i] = completeoverview.Process{PID: 3, Observation: completeoverview.Observation{Status: completeoverview.Exited, Reason: completeoverview.ReasonProcessGone}}
			counts.Exited++
		case 3:
			rows[i] = completeoverview.Process{PID: 4, Observation: completeoverview.Observation{Status: completeoverview.Unavailable, Reason: completeoverview.ReasonReadFailed}}
			counts.Unavailable++
		default:
			counts.Observed++
		}
	}
	snapshot.Processes = completeoverview.ProcessSection{Meta: completeoverview.SectionMeta{GenerationID: snapshot.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: ptr(uint64(n)), CountExact: true, FieldCoverage: counts}, Items: rows}
	return snapshot
}
func volumeSnapshot(which, mode string, at time.Time) completeoverview.Snapshot {
	snapshot := completeoverview.Empty(id("sample_"), at.Add(-600*time.Millisecond), completeoverview.ReasonNotCollected)
	snapshot.CaptureFinishedAt = at.Add(-200 * time.Millisecond)
	n := 125
	if mode == "empty" {
		n = 0
	}
	rows := make([]completeoverview.Volume, n)
	counts := completeoverview.FieldCoverage{}
	for i := range rows {
		path := fmt.Sprintf("/synthetic/%s/mount-%03d", which, i+1)
		if i == 20 || i == 120 {
			path += "-Needle[.*]"
		}
		if mode == "replace" {
			path += "-new"
		}
		row := completeoverview.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: path, Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_42_1", CapacityScope: "agent-mount-namespace", TotalBytes: ptr(uint64(1048576)), AvailableBytes: ptr(uint64(786432)), UsedPercent: ptr(float64(25)), Measurement: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}}
		switch i {
		case 0:
			row.TotalBytes, row.AvailableBytes, row.UsedPercent = ptr(uint64(0)), ptr(uint64(0)), nil
			counts.Observed++
		case 121:
			row.TotalBytes, row.AvailableBytes, row.UsedPercent = nil, nil, nil
			row.Measurement = completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}
			counts.Denied++
		case 122:
			row.Filesystem, row.Kind, row.FilesystemGroup = "tmpfs", "memory", "fs_0_42"
			counts.Observed++
		case 123:
			row.Filesystem, row.Kind, row.FilesystemGroup = "nfs4", "remote", "fs_0_43"
			row.TotalBytes, row.AvailableBytes, row.UsedPercent = nil, nil, nil
			row.Measurement = completeoverview.Observation{Status: completeoverview.Unsupported, Reason: completeoverview.ReasonRemoteFilesystemSkipped}
			counts.Unsupported++
		case 124:
			row.Filesystem, row.Kind, row.FilesystemGroup = "proc", "virtual", "fs_0_44"
			row.TotalBytes, row.AvailableBytes, row.UsedPercent = nil, nil, nil
			row.Measurement = completeoverview.Observation{Status: completeoverview.NotApplicable, Reason: completeoverview.ReasonNotApplicable}
			counts.NotApplicable++
		default:
			counts.Observed++
		}
		rows[i] = row
	}
	snapshot.Volumes = completeoverview.VolumeSection{Meta: completeoverview.SectionMeta{GenerationID: snapshot.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: ptr(uint64(n)), CountExact: true, FieldCoverage: counts}, Items: rows}
	return snapshot
}
func (f *fixture) sample(which, section, mode string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	if section != "processes" && section != "volumes" && section != "both" {
		return errors.New("unsupported fixture section")
	}
	if mode != "complete" && mode != "empty" && mode != "replace" {
		return errors.New("unsupported fixture mode")
	}
	if section == "both" {
		if e := f.sample(which, "processes", mode); e != nil {
			return e
		}
		return f.sample(which, "volumes", mode)
	}
	f.offset.Add(int64(time.Second))
	at := f.now()
	key := which + ":" + section
	seq := f.seq[key] + 1
	generation, e := overviewwire.GenerationID(identity.Approval.DeviceID, section, seq)
	if e != nil {
		return e
	}
	snapshot := processSnapshot(which, mode, at)
	if section == "volumes" {
		snapshot = volumeSnapshot(which, mode, at)
	}
	manifest, chunks, e := overviewgeneration.Build(context.Background(), snapshot, section, generation, nil)
	if e != nil {
		return e
	}
	digest, e := overviewgeneration.ManifestDigest(manifest)
	if e != nil {
		return e
	}
	binding := enrollmentstore.OverviewBinding{Section: section, Sequence: seq, GenerationID: generation, ManifestHash: digest}
	ctx := context.Background()
	if _, e = f.store.OverviewBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); e != nil {
		return e
	}
	for _, chunk := range chunks {
		if _, e = f.store.OverviewAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, at); e != nil {
			return e
		}
	}
	if _, e = f.store.OverviewFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at); e != nil {
		return e
	}
	f.seq[key] = seq
	return nil
}
func (f *fixture) fail(which, section, reason string) error {
	identity, ok := f.devices[which]
	if !ok {
		return errors.New("unknown fixture device")
	}
	if section != "processes" && section != "volumes" {
		return errors.New("unsupported fixture section")
	}
	if reason != "timeout" && reason != "permission_denied" && reason != "source_missing" {
		return errors.New("unsupported fixture failure reason")
	}
	f.offset.Add(int64(time.Second))
	at := f.now()
	key := which + ":" + section
	seq := f.seq[key] + 1
	generation, e := overviewwire.GenerationID(identity.Approval.DeviceID, section, seq)
	if e != nil {
		return e
	}
	report := enrollmentstore.OverviewFailureReport{Section: section, Sequence: seq, GenerationID: generation, AttemptedAt: at, Reason: reason}
	if _, e = f.store.OverviewFailure(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, report, at); e != nil {
		return e
	}
	f.seq[key] = seq
	return nil
}
func (f *fixture) packages(which string, empty bool) error {
	identity := f.devices[which]
	at := f.now()
	generation, e := inventorywire.GenerationID(identity.Approval.DeviceID, 1)
	if e != nil {
		return e
	}
	n := 205
	if empty {
		n = 0
	}
	rows := make([]linuxpackages.PackageRow, n)
	for i := range rows {
		state := "installed"
		if i >= 200 {
			state = "incomplete"
		}
		name := fmt.Sprintf("synthetic-%s-package-%03d", which, i+1)
		rows[i] = linuxpackages.PackageRow{Name: name, Version: "9.0-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "9.0-1", SourceMapping: "binary-default", InstallState: state}
	}
	manifest, chunks, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Rows: rows, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if e != nil {
		return e
	}
	digest, e := fullinventory.ManifestDigest(manifest)
	if e != nil {
		return e
	}
	binding := enrollmentstore.InventoryBinding{Sequence: 1, GenerationID: generation, ManifestHash: digest}
	ctx := context.Background()
	if _, e = f.store.InventoryBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); e != nil {
		return e
	}
	for _, chunk := range chunks {
		if _, e = f.store.InventoryAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, at); e != nil {
			return e
		}
	}
	_, e = f.store.InventoryFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at)
	return e
}
func run() {
	listen := flag.String("listen", "127.0.0.1:19898", "loopback-only fixture")
	dir := flag.String("state", "", "private disposable state")
	web := flag.String("web", "", "built UI directory")
	flag.Parse()
	host, portText, e := net.SplitHostPort(*listen)
	must(e)
	if host != "127.0.0.1" || *dir == "" || *web == "" {
		panic("invalid fixture")
	}
	port, e := strconv.Atoi(portText)
	must(e)
	phase = "issuer"
	issuer, e := makeIssuer(time.Now().UTC())
	must(e)
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://" + *listen, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit = 25
	cfg.InvitationLimit = 25
	cfg.PendingLimit = 25
	phase = "store"
	state, e := enrollmentstore.Open(filepath.Join(*dir, "enrollment", "state.db"), cfg, issuer.IssuerDER())
	must(e)
	defer state.Close()
	must(state.InitializeOverview(context.Background()))
	f := &fixture{store: state, devices: map[string]enrollmentstate.Snapshot{}, seq: map[string]uint64{}}
	f.service, e = enrollmentservice.New(state, issuer, f.now)
	must(e)
	phase = "seed identities"
	f.devices["alpha"] = f.seed(true)
	f.devices["beta"] = f.seed(true)
	f.devices["awaiting"] = f.seed(true)
	phase = "synthetic observations"
	must(f.sample("alpha", "both", "complete"))
	must(f.sample("beta", "both", "empty"))
	must(f.packages("alpha", false))
	must(f.packages("beta", true))
	phase = "operator"
	appStore, e := store.Open(filepath.Join(*dir, "app.db"))
	must(e)
	defer appStore.Close()
	app, e := api.New(appStore, port, *web, model.Device{})
	must(e)
	salt := []byte("browser-test-salt")
	hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
	encoded := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	auth, e := operatorauth.New(operatorauth.Config{PasswordHash: encoded, TTL: time.Hour})
	must(e)
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IssuerDER()}))
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.RootDER()}))
	registry, e := lantrust.NewRegistry(context.Background(), []byte(issuerPEM), lantrust.NewMemoryStore())
	must(e)
	handler, e := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: cfg.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: f.service, EnrollmentBootstrap: api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: cfg.Binding.InstanceID, Profile: "http-test", EnrollmentOrigin: cfg.Binding.Origin, AgentOrigin: "http://127.0.0.1:19893", CollectionProfile: cfg.Binding.CollectionProfile, ServerCAPEM: "", IssuerRootPEM: rootPEM, IssuerPEM: issuerPEM}, Devices: func() ([]model.Device, error) {
		devices, err := f.service.Devices(context.Background(), f.now())
		for i := range devices {
			for label, identity := range f.devices {
				if devices[i].ID == identity.Approval.DeviceID {
					devices[i].Name = "QA synthetic overview " + label
				}
			}
		}
		return devices, err
	}})
	must(e)
	phase = "listen"
	listener, e := net.Listen("tcp", *listen)
	must(e)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4096)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var c struct {
			Action  string `json:"action"`
			Device  string `json:"device"`
			Mode    string `json:"mode"`
			Section string `json:"section"`
			Reason  string `json:"reason"`
			Seconds int64  `json:"seconds"`
		}
		controlErr := json.Unmarshal(scanner.Bytes(), &c)
		phase = "fixture control"
		if controlErr == nil {
			switch c.Action {
			case "info":
			case "sample":
				controlErr = f.sample(c.Device, c.Section, c.Mode)
			case "fail":
				controlErr = f.fail(c.Device, c.Section, c.Reason)
			case "advance":
				if c.Seconds < 0 || c.Seconds > 90000 {
					controlErr = errors.New("unsupported fixture control")
				} else {
					f.offset.Add(int64(time.Duration(c.Seconds) * time.Second))
				}

			default:
				controlErr = errors.New("unsupported fixture control")
			}
		}
		ids := map[string]string{}
		for label, s := range f.devices {
			ids[label] = s.Approval.DeviceID
		}
		reply := map[string]any{"ok": controlErr == nil, "devices": ids, "serviceNow": f.now(), "realNow": time.Now().UTC(), "serviceOffsetSeconds": f.offset.Load() / int64(time.Second), "initialCounts": map[string]any{"alpha": map[string]int{"processes": 205, "volumes": 125, "packageRecords": 205, "installedPackages": 200, "incompletePackages": 5}, "beta": map[string]int{"processes": 0, "volumes": 0, "packageRecords": 0, "installedPackages": 0}}, "operatorTTLSeconds": 3600, "overviewRetentionSeconds": 86400, "pageLimit": 100}
		if controlErr != nil {
			reply["error"] = controlErr.Error()
		}
		must(encoder.Encode(reply))
	}
	must(scanner.Err())
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "Overview browser fixture failed at", phase)
			os.Exit(1)
		}
	}()
	run()
}
