package enrollmentclient

import (
	"fmt"
	"io"
)

// ledgerDisk is used solely by the explicit private persistence path. Generic
// formatting or serialization of in-memory handles must never reveal material.
type ledgerDisk ledgerData

func (ledger) String() string                { return "enrollmentclient.ledger{private:redacted}" }
func (l ledger) GoString() string            { return l.String() }
func (l ledger) Format(f fmt.State, _ rune)  { _, _ = io.WriteString(f, l.String()) }
func (ledger) MarshalJSON() ([]byte, error)  { return []byte(`{"privateRedacted":true}`), nil }
func (session) String() string               { return "enrollmentclient.session{private:redacted}" }
func (s session) GoString() string           { return s.String() }
func (s session) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (session) MarshalJSON() ([]byte, error) { return []byte(`{"privateRedacted":true}`), nil }

// Embedded zero-sized redaction methods protect both store values and pointers
// without value-receiver methods copying the store's mutex.
type storeRedaction struct{}

func (storeRedaction) String() string               { return "enrollmentclient.localStore{private:redacted}" }
func (s storeRedaction) GoString() string           { return s.String() }
func (s storeRedaction) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (storeRedaction) MarshalJSON() ([]byte, error) { return []byte(`{"privateRedacted":true}`), nil }
