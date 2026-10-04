package enrollmenttransport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Ordinary generated fixture identities and owned loopback transport only. A
// withheld body is not verified possession, even when its public leaf is known.
func TestSecurityReviewSignedBodyDoesNotReserveIdentity(t *testing.T) {
	f := newFixture(t, "http-test", true)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var requests atomic.Int64
	_, server, client := f.listen(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				r.Body = &gatedBody{ReadCloser: r.Body, entered: entered, release: release}
			}
			next.ServeHTTP(w, r)
		})
	})
	at := time.Now().UTC()
	raw := frame(t, 1, at)
	first := f.request(t, server.URL, 1, at, raw)
	done := make(chan int, 1)
	go func() {
		res, err := client.Do(first)
		if err != nil {
			done <- 0
			return
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		done <- res.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first ordinary signed request did not reach body gate")
	}
	// It has only supplied a copyable certificate and unverified body so far. The
	// complete legitimate request must still be able to use this same identity.
	response(t, client, f.request(t, server.URL, 1, at, raw), http.StatusOK)
	once.Do(func() { close(release) })
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("ordinary delayed retry returned %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delayed request did not release")
	}
	response(t, client, f.request(t, server.URL, 1, at, raw), http.StatusOK)
}

func TestSecurityReviewCancellationReleasesIngressAdmission(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			var requests atomic.Int64
			_, server, client := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if requests.Add(1) <= MaxInFlight+1 {
						ctx, cancel := context.WithCancel(r.Context())
						cancel()
						r = r.WithContext(ctx)
					}
					next.ServeHTTP(w, r)
				})
			})
			at := time.Now().UTC()
			raw := frame(t, 1, at)
			for range MaxInFlight + 1 {
				response(t, client, f.request(t, server.URL, 1, at, raw), http.StatusServiceUnavailable)
			}
			response(t, client, f.request(t, server.URL, 1, at, raw), http.StatusOK)
		})
	}
}

func TestSecurityReviewCopiedIngressSharesCertificateAdmission(t *testing.T) {
	f := newFixture(t, "http-test", true)
	original, _, _ := f.listen(t, nil)
	copied := *original
	// Sequential exclusion is retained across copies.
	release, ok := original.admitCertificate([]byte("synthetic identity one"))
	if !ok {
		t.Fatal("first identity denied")
	}
	if _, ok := copied.admitCertificate([]byte("synthetic identity one")); ok {
		t.Fatal("copy bypassed identity exclusion")
	}
	release()
	// Concurrent distinct-key activity requires one shared mutex as well as the
	// shared map. Running under -race detects a mutex copied away from its map.
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			handle := original
			if worker%2 == 1 {
				handle = &copied
			}
			for iteration := range 100 {
				release, ok := handle.admitCertificate([]byte(fmt.Sprintf("synthetic-%d-%d", worker, iteration)))
				if ok {
					release()
					release()
				}
			}
		}(worker)
	}
	wg.Wait()
	first, ok := original.admitCertificate([]byte("synthetic final one"))
	if !ok {
		t.Fatal("first capacity not returned")
	}
	defer first()
	second, ok := copied.admitCertificate([]byte("synthetic final two"))
	if !ok {
		t.Fatal("second capacity not returned")
	}
	defer second()
	if _, ok := original.admitCertificate([]byte("synthetic over capacity")); ok {
		t.Fatal("global identity capacity expanded")
	}
}
