package enrollmenttransport

import (
	"net/http"
	"strconv"
	"time"
)

// writeAccountBoundJSON must run before the caller releases its authority lease.
// net/http can buffer Write until after ServeHTTP returns; live permits must be
// flushed under the lease and the caller's bounded write deadline. Handoff does
// not prove endpoint receipt and never refunds a consumed claim.
func writeAccountBoundJSON(w http.ResponseWriter, raw []byte, live bool) {
	if live && !accountResponseCanFlush(w) {
		http.Error(w, "response unavailable", http.StatusServiceUnavailable)
		return
	}
	if live {
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	n, err := w.Write(raw)
	if !live {
		return
	}
	if err != nil || n != len(raw) {
		// Do not allow finishRequest to flush remaining permit bytes after the
		// deferred lease release. net/http closes/resets this response on abort.
		abortAccountResponse(w)
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		abortAccountResponse(w)
	}
}

func accountResponseCanFlush(w http.ResponseWriter) bool {
	for depth := 0; depth < 32; depth++ {
		switch v := w.(type) {
		case interface{ FlushError() error }:
			return true
		case http.Flusher:
			return true
		case interface{ Unwrap() http.ResponseWriter }:
			w = v.Unwrap()
		default:
			return false
		}
	}
	return false
}

// net/http's panic cleanup may flush its connection buffer. Expire the already
// supported write deadline before releasing authority so cleanup cannot emit a
// remaining tail even when an outer wrapper manufactured the write/flush error.
func abortAccountResponse(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
	panic(http.ErrAbortHandler)
}

// The current ingress serves HTTP/1. net/http HTTP/2 Flush does not provide the
// same connection-buffer completion fence. Do not issue a live permit over a
// future HTTP/2 listener until its handoff ordering has a separate contract.
func writeAccountBoundJSONResponse(w http.ResponseWriter, r *http.Request, raw []byte, live bool) {
	if live && r.ProtoMajor != 1 {
		http.Error(w, "response protocol unavailable", http.StatusServiceUnavailable)
		return
	}
	writeAccountBoundJSON(w, raw, live)
}
