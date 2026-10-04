package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInvitationCreationAdvertisesExactPublicDownloadChecksum(t *testing.T) {
	now := time.Now().UTC()
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral checksum root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("checksum-root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		t.Fatal(e)
	}
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral checksum issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("checksum-issuer")}
	id, e := x509.CreateCertificate(rand.Reader, issuerTemplate, root, ip, rk)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(id)
	issuer, e := enrollmentissuer.New(id, rd, ik, hex.EncodeToString(sum[:]), now)
	if e != nil {
		t.Fatal(e)
	}
	binding := enrollmentstate.Binding{InstanceID: "manager_00000000000000000000000000000001", Profile: "http-test", Origin: "http://127.0.0.1:8787", CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: issuer.Fingerprint()}
	config := enrollmentstate.DefaultConfig(binding)
	config.RecordLimit = 25
	config.InvitationLimit = 25
	config.PendingLimit = 25
	store, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "enrollment.db"), config, id)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := enrollmentservice.New(store, issuer, nil)
	if e != nil {
		t.Fatal(e)
	}
	pemText := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	b := EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: binding.Origin, AgentOrigin: "http://127.0.0.1:8788", CollectionProfile: binding.CollectionProfile, IssuerRootPEM: pemText(rd), IssuerPEM: pemText(id)}
	app := setup(t)
	h := &operatorHandler{app: app, enrollment: service, enrollmentBootstrap: b}
	r := httptest.NewRequest("POST", binding.Origin+"/api/enrollment/invitations", strings.NewReader(`{"requestId":"request_00000000000000000000000000000001","platform":"linux"}`))
	r.Header.Set("Origin", binding.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", app.csrf)
	w := httptest.NewRecorder()
	h.enrollmentOperator(w, r)
	var created struct {
		Bootstrap       EnrollmentBootstrap `json:"bootstrap"`
		BootstrapSHA256 string              `json:"bootstrapSHA256"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.BootstrapSHA256 == "" {
		t.Fatal("creation checksum absent", w.Code)
	}
	raw, want, e := publicBootstrapBytes(b, created.Bootstrap.InvitationID)
	if e != nil || created.BootstrapSHA256 != want {
		t.Fatal("creation byte contract mismatch")
	}
	download := httptest.NewRecorder()
	get := httptest.NewRequest("GET", publicBootstrapPrefix+created.Bootstrap.InvitationID, nil)
	get.RemoteAddr = "127.0.0.1:1234"
	servePublicBootstrap(download, get, b, &bootstrapAdmission{})
	if download.Code != 200 || download.Body.String() != string(raw) {
		t.Fatal("creation/download bytes differ")
	}
	snapshots, e := service.Snapshots(context.Background())
	if e != nil || len(snapshots) != 1 || snapshots[0].State != enrollmentstate.Created {
		t.Fatal("public retrieval changed lifecycle")
	}
}
