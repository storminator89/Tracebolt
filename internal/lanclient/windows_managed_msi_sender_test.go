//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	managed "localrmm/internal/windowsmanagedmsi"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestManagedMSIRealTLSTransportFrameBoundsAndPolicy(t *testing.T) {
	var seen int
	body := bytes.Repeat([]byte("x"), managed.MaxChunkBytes)
	chunk := managed.Chunk{TransferID: "transfer_11111111111111111111111111111111", Index: 0, PermitDigest: managed.Digest([]byte("permit")), Digest: managed.Digest(body), Data: body}
	raw, _ := json.Marshal(chunk)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.Method != "POST" || r.URL.Path != managedMSIPrefix+"chunk" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Range") != "" {
			t.Error("unexpected transport shape")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	defer server.Close()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	s := &windowsManagedMSISender{material: Material{config: Config{ManagerOrigin: server.URL}}, client: newHTTPClient(tlsConfig, false)}
	defer s.Close()
	got, e := s.request(context.Background(), managedMSIPrefix+"chunk", []byte("{}"))
	if e != nil || !bytes.Equal(got, raw) || len(got) > managed.MaxFrameBytes || seen != 1 {
		t.Fatal("bounded TLS request", e, seen)
	}
	if _, e = s.request(context.Background(), "/arbitrary", []byte("{}")); e == nil || seen != 1 {
		t.Fatal("arbitrary path")
	}
	if _, e = s.request(context.Background(), managedMSIPrefix+"chunk", make([]byte, managed.MaxFrameBytes+1)); e == nil || seen != 1 {
		t.Fatal("unbounded request")
	}
	transport := s.client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || s.client.CheckRedirect == nil {
		t.Fatal("transport policy widened")
	}
}
func TestManagedMSITLSRedirectCompressionAndResponseBounds(t *testing.T) {
	for _, mode := range []string{"redirect", "compression", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/other")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "compression":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write([]byte("{}"))
				case "oversize":
					w.Write(make([]byte, managed.MaxFrameBytes+1))
				}
			}))
			defer server.Close()
			s := &windowsManagedMSISender{material: Material{config: Config{ManagerOrigin: server.URL}}, client: newHTTPClient(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), false)}
			defer s.Close()
			if _, e := s.request(context.Background(), managedMSIPrefix+"poll", []byte("{}")); e == nil || calls != 1 {
				t.Fatal("unsafe transport admitted", mode, e, calls)
			}
		})
	}
}
func TestManagedMSISenderMissingGrantNeverOpensPeerOrNetwork(t *testing.T) {
	s := &windowsManagedMSISender{local: func(Material) (WindowsManagedMSIRelayGrant, error) {
		return WindowsManagedMSIRelayGrant{}, os.ErrNotExist
	}}
	if got := s.Run(context.Background()); got != "disabled" {
		t.Fatal(got)
	}
}

func TestManagedMSIOnlyReportConflictAllowsFreshPollClassification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusConflict) }))
	defer server.Close()
	s := &windowsManagedMSISender{material: Material{config: Config{ManagerOrigin: server.URL}}, client: newHTTPClient(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), false)}
	defer s.Close()
	for _, op := range []string{"report", "poll", "chunk"} {
		_, e := s.request(context.Background(), managedMSIPrefix+op, []byte("{}"))
		if (e == errManagedMSIReportRejected) != (op == "report") {
			t.Fatal("unexpected conflict classification", op, e)
		}
	}
}
