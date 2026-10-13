package macosinventory

import (
	"bytes"
	"context"
	"io"
	"sync"
)

type outputBudget struct {
	mu           sync.Mutex
	buffer       bytes.Buffer
	total, limit int
	overflow     bool
	stderrSeen   bool
	cancel       context.CancelFunc
}
type outputWriter struct {
	owner  *outputBudget
	retain bool
}

func newOutputBudget(limit int, cancel context.CancelFunc) *outputBudget {
	return &outputBudget{limit: limit, cancel: cancel}
}
func (b *outputBudget) stdout() io.Writer { return outputWriter{b, true} }
func (b *outputBudget) stderr() io.Writer { return outputWriter{b, false} }
func (w outputWriter) Write(p []byte) (int, error) {
	b := w.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return 0, ErrBounds
	}
	if len(p) > b.limit-b.total {
		b.overflow = true
		b.cancel()
		return 0, ErrBounds
	}
	b.total += len(p)
	if !w.retain && len(p) > 0 {
		b.stderrSeen = true
	}
	if w.retain {
		_, _ = b.buffer.Write(p)
	}
	return len(p), nil
}
func (b *outputBudget) exceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.overflow }
func (b *outputBudget) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func (b *outputBudget) hasStderr() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.stderrSeen }
