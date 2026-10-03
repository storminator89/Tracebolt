package main

import (
	"localrmm/internal/analysis"
	"net/http"
	"time"
)

// The write deadline must outlast a bounded AI attempt so the client can receive
// either the validated result or the explicit timeout state.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: analysis.MaxTimeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
}
