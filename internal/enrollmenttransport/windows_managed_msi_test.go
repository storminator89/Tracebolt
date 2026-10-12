package enrollmenttransport

import (
	"bytes"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http"
	"strings"
	"testing"
)

func TestManagedMSIFramingDoesNotPromotePreparedOrURLs(t *testing.T) {
	fresh := func() *http.Request {
		r, e := http.NewRequest("POST", "https://manager.test/v1/windows-managed-msi/poll", bytes.NewReader([]byte("{}")))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	if !validManagedMSIRequest(fresh(), "manager.test") {
		t.Fatal("canonical frame")
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.URL.Path = "/v1/windows-software-jobs/poll" }, func(r *http.Request) { r.URL.RawQuery = "url=https://example.test/payload" }, func(r *http.Request) { r.Header.Set("Range", "bytes=0-32767") }, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, func(r *http.Request) { r.Header.Set("Forwarded", "host=manager.test") }, func(r *http.Request) { r.Header.Set("Content-Disposition", "attachment; filename=x.msi") }, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }} {
		r := fresh()
		change(r)
		if validManagedMSIRequest(r, "manager.test") {
			t.Fatal("ambiguous frame accepted")
		}
	}
}
func TestManagedMSIChunkFrameFits64KiB(t *testing.T) {
	data := bytes.Repeat([]byte{1}, msi.MaxChunkBytes)
	c := msi.Chunk{TransferID: "transfer_" + strings.Repeat("1", 32), Index: 4095, PermitDigest: msi.Digest([]byte("permit")), Digest: msi.Digest(data), Data: data}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > msi.MaxFrameBytes {
		t.Fatal(len(raw), e)
	}
	for _, op := range []string{"poll", "chunk", "report"} {
		if managedMSIBodyLimit(windowsManagedMSIPrefix+op) == 0 {
			t.Fatal(op)
		}
	}
	for _, op := range []string{"upload", "download", "range", "redirect", "install-claim"} {
		if managedMSIBodyLimit(windowsManagedMSIPrefix+op) != 0 {
			t.Fatal(op)
		}
	}
}
