package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const (
	ResultVersion      = "tracebolt.analysis.v1"
	PromptVersion      = "tracebolt.diagnostics-prompt.v1"
	RunbookVersion     = "tracebolt.read-only-runbooks.v1"
	MaxResponseBytes   = 16 * 1024
	MaxProviderBytes   = 64 * 1024
	MaxRequestBytes    = 64 * 1024
	MaxClaims          = 5
	MaxMissingData     = 8
	MaxOutputTextBytes = 512
	DefaultTimeout     = 15 * time.Second
	MaxTimeout         = 30 * time.Second
)

type RunbookID string

const (
	CheckNone    RunbookID = "none"
	CheckService RunbookID = "service"
	CheckStorage RunbookID = "storage"
	CheckNetwork RunbookID = "network"
)

func knownRunbook(id RunbookID) bool {
	return id == CheckNone || id == CheckService || id == CheckStorage || id == CheckNetwork
}

type Claim struct {
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidenceIDs"`
}

// Findings contains suggestions only. Citation validation checks identity and
// structure, not whether the cited observation logically supports a claim.
type Findings struct {
	ObservedEvidenceIDs []string  `json:"observedEvidenceIDs"`
	Hypotheses          []Claim   `json:"hypotheses"`
	Counterevidence     []Claim   `json:"counterevidence"`
	MissingData         []string  `json:"missingData"`
	NextCheck           RunbookID `json:"nextCheck"`
}

type Provenance struct {
	Method         string `json:"method"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	PromptVersion  string `json:"promptVersion"`
	RunbookVersion string `json:"runbookVersion"`
	RuleID         string `json:"ruleId"`
	PacketSHA256   string `json:"packetSHA256"`
	Destination    string `json:"destination"`
	EndpointOrigin string `json:"endpointOrigin"`
}

type Baseline struct {
	Summary     string     `json:"summary"`
	EvidenceIDs []string   `json:"evidenceIDs"`
	NextCheck   RunbookID  `json:"nextCheck"`
	NextSteps   []string   `json:"nextSteps"`
	Provenance  Provenance `json:"provenance"`
}

type AIResult struct {
	Status   string    `json:"status"`
	Reason   string    `json:"reason"`
	Findings *Findings `json:"findings"`
	// These steps come only from the server's fixed read-only runbooks.
	NextSteps  []string   `json:"nextSteps"`
	Provenance Provenance `json:"provenance"`
}

type Result struct {
	SchemaVersion      string    `json:"schemaVersion"`
	ID                 string    `json:"id"`
	Fingerprint        string    `json:"fingerprint"`
	GeneratedAt        time.Time `json:"generatedAt"`
	Packet             Packet    `json:"packet"`
	Baseline           Baseline  `json:"baseline"`
	AI                 AIResult  `json:"ai"`
	RootCauseConfirmed bool      `json:"rootCauseConfirmed"`
	Limitations        []string  `json:"limitations"`
}

// Provider is an internal code seam, never supplied by an HTTP request. An
// implementation must honor cancellation and enforce its transport boundary.
// Only OllamaProvider is a shipped live provider; test fakes do no inference.
type Provider interface {
	Identity() ProviderIdentity
	Generate(context.Context, ProviderRequest) ([]byte, error)
}

type ProviderIdentity struct {
	Name           string
	Model          string
	Destination    string
	EndpointOrigin string
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ProviderRequest struct {
	Messages []Message
	Schema   json.RawMessage
}

var (
	ErrNotConfigured    = errors.New("local model is not configured")
	ErrUnavailable      = errors.New("local model is unavailable")
	ErrInvalidResponse  = errors.New("local model returned an invalid response")
	ErrResponseTooLarge = errors.New("local model response exceeds bounds")
	ErrBusy             = errors.New("another local analysis is running")
)
