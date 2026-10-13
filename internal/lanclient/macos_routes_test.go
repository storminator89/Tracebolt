package lanclient

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMacOSFixedBootstrapAndTelemetryRoutes(t *testing.T) {
	if _, err := NewMacOSBootstrapHTTPClient("http://127.0.0.1:1", "http-test", nil); err == nil {
		t.Fatal("HTTP bootstrap admitted")
	}
	calls := 0
	tr := &bootstrapTransport{origin: "https://manager.invalid", authority: "manager.invalid", pathPrefix: "/v2/macos/enrollment/", next: bootstrapRouteSink(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	for _, verb := range []string{"challenge", "claim", "status", "credential", "activate", "renewal/challenge", "renewal/status", "renewal/issue", "renewal/activate"} {
		r, _ := http.NewRequest("POST", tr.origin+tr.pathPrefix+verb, bytes.NewReader([]byte(`{}`)))
		res, err := tr.RoundTrip(r)
		if err != nil {
			t.Fatal("fixed verb rejected", verb)
		}
		res.Body.Close()
	}
	for _, path := range []string{"/v2/enrollment/claim", "/v2/windows/enrollment/claim", "/v2/macos/enrollment/unknown", "/v2/macos/enrollment/%63laim", "/v2/macos/enrollment/claim?x=1"} {
		r, _ := http.NewRequest("POST", tr.origin+path, bytes.NewReader([]byte(`{}`)))
		if _, err := tr.RoundTrip(r); err == nil {
			t.Fatal("foreign route admitted", path)
		}
	}
	if calls != 9 {
		t.Fatal("rejected request reached transport")
	}
	if telemetryPathForOS(Config{}, "darwin") != MacOSTelemetryPath || telemetryPathForOS(Config{}, "linux") == MacOSTelemetryPath {
		t.Fatal("runtime telemetry routing")
	}
}
