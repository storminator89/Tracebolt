package inventorywire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/updategeneration"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cachedUpdatesMessages(t *testing.T, n int) (string, updategeneration.Manifest, []updategeneration.Chunk) {
	t.Helper()
	id, err := CachedUpdatesGenerationID("agent_"+strings.Repeat("1", 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 4, 9, 0, 0, 123, time.UTC)
	oldest, age := at.Add(-72*time.Hour), uint64(72*60*60)
	release, version, codename := "debian", "13", "trixie"
	count, checked, unknown, held := uint32(n), uint32(n), uint32(1), uint32(0)
	installed := checked + unknown
	rows := make([]cachedupdates.Candidate, n)
	for i := range rows {
		rows[i] = cachedupdates.Candidate{Name: fmt.Sprintf("fixture-update-%06d", i), Architecture: "amd64", InstalledVersion: "1.0", CandidateVersion: "2.0", State: "candidate_only", Installability: "not_evaluated"}
	}
	s := cachedupdates.Snapshot{SchemaVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, GenerationID: id, CollectedAt: at, Release: linuxpackages.ReleaseFields{ID: &release, VersionID: &version, VersionCodename: &codename}, Metadata: cachedupdates.Metadata{Freshness: "stale", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}, InstalledCount: &installed, CheckedCount: &checked, CandidateCount: &count, HeldCount: &held, UnknownCount: &unknown, Coverage: "partial", Reason: cachedupdates.ReasonCandidateUnknown, Items: append([]cachedupdates.Candidate{}, rows[:min(n, cachedupdates.MaxRows)]...), Truncated: n > cachedupdates.MaxRows}
	if s.Truncated {
		s.Reason = cachedupdates.ReasonItemLimit
	}
	for cachedupdates.Validate(s) != nil {
		if len(s.Items) == 0 {
			t.Fatal("invalid synthetic update snapshot")
		}
		s.Items = s.Items[:len(s.Items)-1]
		s.Truncated = true
		s.Reason = cachedupdates.ReasonByteLimit
	}
	m, chunks, err := updategeneration.Build(context.Background(), updategeneration.SourceInventory{Snapshot: s, Rows: rows, Complete: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := updategeneration.ManifestDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	return hash, m, chunks
}
func cachedUpdatesReceiptFixture(t *testing.T, op string, body []byte, result any) []byte {
	t.Helper()
	m, err := DecodeCachedUpdatesMessage(op, body)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(map[string]any{"schemaVersion": CachedUpdatesReceiptVersion, "operation": op, "sequence": strconv.FormatUint(m.Sequence, 10), "generationId": m.GenerationID, "manifestHash": m.ManifestHash, "requestSha256": hex.EncodeToString(sum[:]), "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestCachedUpdatesWireStrictTypedPurposeAndExactReceipt(t *testing.T) {
	hash, m, chunks := cachedUpdatesMessages(t, 129)
	at := m.CollectedAt.Add(time.Minute)
	cases := []struct {
		op, hash        string
		payload, result any
	}{
		{"begin", hash, m, map[string]any{"startedAt": at, "expiresAt": at.Add(15 * time.Minute)}},
		{"append", hash, chunks[0], map[string]any{"ordinal": 0, "rows": 128, "receivedAt": at}},
		{"finalize", hash, struct{}{}, map[string]any{"collectedAt": m.CollectedAt, "completedAt": at}},
		{"abort", hash, struct{}{}, map[string]any{"aborted": true}},
		{"status", hash, struct{}{}, map[string]any{"state": "pending", "acceptedChunks": 0, "expectedChunks": 2, "acceptedRows": 0, "startedAt": at, "expiresAt": at.Add(15 * time.Minute), "completedAt": ""}},
		{"failure", "", map[string]any{"attemptedAt": m.CollectedAt, "reason": "source_changed"}, map[string]any{"attemptedAt": m.CollectedAt, "receivedAt": at, "reason": "source_changed"}},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			raw, err := EncodeCachedUpdatesMessage(tc.op, 1, m.GenerationID, tc.hash, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := DecodeCachedUpdatesMessage(tc.op, raw)
			if err != nil || msg.Manifest != nil || msg.Chunk != nil {
				t.Fatal("updates relabeled as package rows", err)
			}
			if tc.op == "begin" && (msg.UpdateManifest == nil || msg.UpdateManifest.UnknownCount != 1 || *msg.UpdateManifest.Metadata.AgeSeconds != 72*60*60) {
				t.Fatal("original metadata lost")
			}
			if tc.op == "append" && (msg.UpdateChunk == nil || len(msg.UpdateChunk.Items) != 128) {
				t.Fatal("typed update rows lost")
			}
			if _, err = DecodeMessage(tc.op, raw); err == nil {
				t.Fatal("update admitted as package message")
			}
			switched := bytes.Replace(raw, []byte(CachedUpdatesMessageVersion), []byte(MessageVersion), 1)
			if _, err = DecodeCachedUpdatesMessage(tc.op, switched); err == nil {
				t.Fatal("package schema admitted as updates")
			}
			if tc.op == "begin" || tc.op == "append" {
				if _, err = DecodeMessage(tc.op, switched); err == nil {
					t.Fatal("update payload admitted by package parser")
				}
			}
			for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Replace(raw, []byte(`"payload":`), []byte(`"payload":null,"extra":`), 1), append(bytes.Clone(raw), []byte(`{}`)...)} {
				if _, err = DecodeCachedUpdatesMessage(tc.op, bad); err == nil {
					t.Fatal("ambiguous message admitted")
				}
			}
			ack := cachedUpdatesReceiptFixture(t, tc.op, raw, tc.result)
			if _, err = DecodeCachedUpdatesReceipt(ack, tc.op, raw); err != nil {
				t.Fatal(err)
			}
			for _, bad := range [][]byte{bytes.Replace(ack, []byte(CachedUpdatesReceiptVersion), []byte(ReceiptVersion), 1), bytes.Replace(ack, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), append(bytes.Clone(ack), []byte(`{}`)...)} {
				if _, err = DecodeCachedUpdatesReceipt(bad, tc.op, raw); err == nil {
					t.Fatal("cross-domain or ambiguous receipt admitted")
				}
			}
			if _, err = DecodeCachedUpdatesReceipt(ack, tc.op, append([]byte(" "), raw...)); err == nil {
				t.Fatal("exact request binding lost")
			}
		})
	}
	packageHash, pm, pc := inventoryMessages(t)
	for _, tc := range []struct {
		op      string
		payload any
	}{{"begin", pm}, {"append", pc[0]}} {
		if _, err := EncodeCachedUpdatesMessage(tc.op, 1, pm.GenerationID, packageHash, tc.payload); err == nil {
			t.Fatal("package payload admitted as updates")
		}
	}
}
func TestCachedUpdatesGenerationPathAndSignatureDomains(t *testing.T) {
	agent := "agent_" + strings.Repeat("1", 32)
	old, _ := GenerationID(agent, 1)
	update, _ := CachedUpdatesGenerationID(agent, 1)
	if old == update {
		t.Fatal("generation domain reused")
	}
	for _, seq := range []uint64{0, MaxSequence + 1} {
		if _, err := CachedUpdatesGenerationID(agent, seq); err == nil {
			t.Fatal("invalid sequence")
		}
	}
	pair, registry := inventoryFixture(t)
	origin := "http://127.0.0.1:8788"
	uv, err := NewCachedUpdatesVerifier(Config{Origin: origin, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	pv, err := New(Config{Origin: origin, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	hash, m, _ := cachedUpdatesMessages(t, 1)
	body, err := EncodeCachedUpdatesMessage("begin", 1, m.GenerationID, hash, m)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r, err := NewCachedUpdatesSignedRequest(context.Background(), origin, pair, "begin", 1, time.Now().UTC(), body)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	verified, err := uv.Verify(request())
	if err != nil || !bytes.Equal(verified.Body, body) {
		t.Fatal("fixed update proof failed", err)
	}
	if _, err = pv.Verify(request()); err == nil {
		t.Fatal("package verifier accepted update route")
	}
	r := request()
	r.URL.Path = PathPrefix + "begin"
	if _, err = pv.Verify(r); err == nil {
		t.Fatal("rerouted update proof admitted as package")
	}
	r = request()
	cert, _ := x509.ParseCertificate(pair.Certificate[0])
	// Same correct update path, origin/body/certificate/time, but package domain.
	sig := ed25519.Sign(pair.PrivateKey.(ed25519.PrivateKey), transcript(origin, r.URL.Path, lantrust.Fingerprint(cert), r.Header.Get(SequenceHeader), r.Header.Get(SignedAtHeader), body))
	r.Header.Set(SignatureHeader, base64.RawStdEncoding.EncodeToString(sig))
	if _, err = uv.Verify(r); err == nil {
		t.Fatal("package signature domain admitted by update verifier")
	}
	for _, mutate := range []func(*http.Request){func(r *http.Request) { r.URL.RawQuery = "x=1" }, func(r *http.Request) { r.URL.Path = CachedUpdatesPathPrefix + "operator" }, func(r *http.Request) { r.Header["x-tracebolt-inventory-sequence"] = []string{"1"} }} {
		r = request()
		mutate(r)
		if _, err = uv.Verify(r); err == nil {
			t.Fatal("ambiguous update framing admitted")
		}
	}
}

func TestUnsupportedFailureIsExplicitAndUpdateDomainOnly(t *testing.T) {
	at := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	id, _ := CachedUpdatesGenerationID("agent_"+strings.Repeat("1", 32), 1)
	payload := map[string]any{"attemptedAt": at, "reason": "not_supported"}
	raw, e := EncodeCachedUpdatesMessage("failure", 1, id, "", payload)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeCachedUpdatesMessage("failure", raw)
	if e != nil || decoded.FailureReason != "not_supported" {
		t.Fatal("unsupported source obscured", e)
	}
	if _, e = EncodeMessage("failure", 1, id, "", payload); e == nil {
		t.Fatal("new reason widened old package wire")
	}
}
