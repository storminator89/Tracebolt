package signedhttp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestWindowsTelemetryPathIsFiniteAndSigned(t *testing.T) {
	f := makeFixture(t, nil) // Entire registry and public certificate fixture is in memory.
	at := time.Now().UTC()
	for _, path := range []string{Path, WindowsPath} {
		v, err := New(Config{Origin: testOrigin, Registry: f.registry, Path: path})
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewSignedRequestForPath(context.Background(), testOrigin, path, f.pair, 1, at, testBody)
		if err != nil || r.URL.Path != path {
			t.Fatal("fixed route rejected", err)
		}
		got, err := v.Verify(r)
		if err != nil || !bytes.Equal(got.Body, testBody) {
			t.Fatal("path signature failed", err)
		}
		other := Path
		if path == Path {
			other = WindowsPath
		}
		wrong, _ := NewSignedRequestForPath(context.Background(), testOrigin, other, f.pair, 1, at, testBody)
		if _, err := v.Verify(wrong); !errors.Is(err, ErrRequest) {
			t.Fatal("cross-path request accepted")
		}
		tampered, _ := NewSignedRequestForPath(context.Background(), testOrigin, other, f.pair, 1, at, testBody)
		tampered.URL.Path = path
		if _, err := v.Verify(tampered); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("rewritten path retained signature authority")
		}
	}
	legacy, _ := NewSignedRequest(context.Background(), testOrigin, f.pair, 1, at, testBody)
	explicit, _ := NewSignedRequestForPath(context.Background(), testOrigin, Path, f.pair, 1, at, testBody)
	if legacy.URL.String() != explicit.URL.String() || legacy.Header.Get(SignatureHeader) != explicit.Header.Get(SignatureHeader) {
		t.Fatal("old wire signature changed")
	}
	for _, path := range []string{"/", WindowsPath + "/", WindowsPath + "?x=1", "/v1/windows/agent/%74elemetry", "http://fixture.invalid", ""} {
		if _, err := NewSignedRequestForPath(context.Background(), testOrigin, path, f.pair, 1, at, testBody); !errors.Is(err, ErrConfiguration) {
			t.Fatal("arbitrary signing path allowed")
		}
		if path != "" {
			if _, err := New(Config{Origin: testOrigin, Registry: f.registry, Path: path}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("arbitrary verifier path allowed")
			}
		}
	}
}
