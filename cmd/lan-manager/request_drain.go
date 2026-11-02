package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

var errManagerHTTPDrainIncomplete = errors.New("manager HTTP shutdown is incomplete; state ownership retained until handlers finish or process exits")
var errManagerHTTPShutdownInterrupted = errors.New("manager HTTP shutdown required connection termination")

// Both operator and endpoint ingress use the same admission/ownership gate.
// Closing admission and observing zero active handlers share one mutex, so a
// later request cannot race a drain and regain access to closing state.
type managerRequestDrain struct {
	mu          sync.Mutex
	stopping    bool
	active      int
	done        chan struct{}
	cleanupOnce sync.Once
}

func newManagerRequestDrain() *managerRequestDrain {
	return &managerRequestDrain{done: make(chan struct{})}
}

func (d *managerRequestDrain) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		if d.stopping {
			d.mu.Unlock()
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "manager shutdown in progress", http.StatusServiceUnavailable)
			return
		}
		d.active++
		d.mu.Unlock()
		defer func() {
			d.mu.Lock()
			d.active--
			if d.stopping && d.active == 0 {
				close(d.done)
			}
			d.mu.Unlock()
		}()
		next.ServeHTTP(w, r)
	})
}

func (d *managerRequestDrain) Stop() {
	d.mu.Lock()
	if !d.stopping {
		d.stopping = true
		if d.active == 0 {
			close(d.done)
		}
	}
	d.mu.Unlock()
}

func (d *managerRequestDrain) Drained() bool {
	select {
	case <-d.done:
		return true
	default:
		return false
	}
}

// Called only after run's worker-join defers. It never blocks the shutdown
// caller indefinitely. An unfinished handler retains all stores and the writer
// lease until it actually returns. The real CLI treats incomplete shutdown as a
// fatal error and exits; process exit terminates handlers and releases OS locks.
// An in-process caller must not treat that error as a clean stop/restart grant.
func (d *managerRequestDrain) CloseAfterDrain(closeState func()) {
	d.Stop()
	d.cleanupOnce.Do(func() {
		if d.Drained() {
			closeState()
			return
		}
		go func() { <-d.done; closeState() }()
	})
}

// Preserve the existing total graceful-shutdown budget. Timeout closes both
// servers' connections, but Close is not a handler join. A hung/slow handler
// therefore produces a fixed failure and cannot release ownership prematurely.
func stopManagerHTTP(operators, agents *http.Server, drain *managerRequestDrain, budget time.Duration) error {
	drain.Stop()
	shutdown, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	operatorErr := operators.Shutdown(shutdown)
	agentErr := agents.Shutdown(shutdown)
	if operatorErr != nil || agentErr != nil {
		_ = operators.Close()
		_ = agents.Close()
	}
	if !drain.Drained() {
		return errManagerHTTPDrainIncomplete
	}
	if operatorErr != nil || agentErr != nil {
		return errManagerHTTPShutdownInterrupted
	}
	return nil
}
