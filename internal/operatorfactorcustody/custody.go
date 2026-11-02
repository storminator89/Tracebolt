// Package operatorfactorcustody stages explicit local TOTP custody material.
// It never opens account authority, commits revisions, starts a service or
// reveals a secret through an API result. Linux-only custody is opt-in.
package operatorfactorcustody

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/operatorfactorclient"
	"sync"
)

type Options struct {
	LanConfig        string
	RuntimeUID       int
	ActorID          string
	ExpectedRevision uint64
	HandoffFile      string
	Acknowledge      bool
	ReplaceStale     bool
}

func (Options) String() string               { return "operatorfactorcustody.Options{redacted}" }
func (Options) GoString() string             { return "operatorfactorcustody.Options{redacted}" }
func (Options) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type Result struct {
	ProposalCreated bool `json:"proposalCreated"`
	HandoffCreated  bool `json:"handoffCreated"`
	Archived        bool `json:"archived"`
}

var (
	ErrConfiguration = errors.New("factor custody configuration rejected")
	ErrTarget        = errors.New("factor custody target review mismatch")
	ErrExisting      = errors.New("factor custody destination already exists")
	ErrUncertain     = errors.New("factor custody state uncertain; preserve files")
	ErrChanged       = errors.New("factor custody pinned inputs changed")
	ErrUnsupported   = errors.New("factor custody unsupported platform")
)

func Code(err error) string {
	switch {
	case err == nil:
		return "staged"
	case errors.Is(err, ErrConfiguration):
		return "configuration"
	case errors.Is(err, ErrTarget):
		return "target_review"
	case errors.Is(err, ErrExisting):
		return "existing_state"
	case errors.Is(err, ErrChanged):
		return "pinned_input_changed"
	case errors.Is(err, ErrUncertain):
		return "custody_uncertain"
	case errors.Is(err, ErrUnsupported):
		return "unsupported_platform"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	default:
		return "custody_uncertain"
	}
}
func StableCode(err error) string { return Code(err) }

type Plan struct {
	mu      sync.Mutex
	used    bool
	options Options
	client  operatorfactorclient.Config
	data    any // platform-private pinned inputs; never serialized
}

func (*Plan) String() string   { return "operatorfactorcustody.Plan{redacted}" }
func (*Plan) GoString() string { return "operatorfactorcustody.Plan{redacted}" }
func (*Plan) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Redacted bool `json:"redacted"`
	}{true})
}
func (p *Plan) ClientConfig() operatorfactorclient.Config {
	if p == nil {
		return operatorfactorclient.Config{}
	}
	return operatorfactorclient.Config{Origin: p.client.Origin, ServerCertificate: append([]byte(nil), p.client.ServerCertificate...)}
}
