// Package linuxprocesswatch evaluates opt-in, discrete complete process generations.
// It performs no collection, storage, network requests or host actions.
package linuxprocesswatch

import (
	"errors"
	"time"
)

const (
	MaxRules      = 8
	MaxIncidents  = 128
	MaxBytes      = 196608
	MaxDevices    = 25
	RetentionDays = 30
	Retention     = 30 * 24 * time.Hour
	MaxAge        = 120 * time.Second
	SchemaVersion = "tracebolt.linux-process-watches.v1"
)

var (
	ErrInvalid  = errors.New("invalid process watch state or request")
	ErrConflict = errors.New("process watch revision conflict")
	ErrSource   = errors.New("process watch source changed or unavailable")
	ErrClock    = errors.New("process watch clock rollback")
	ErrCapacity = errors.New("process watch capacity exhausted")
)

type Generation struct {
	Sequence          string    `json:"sequence"`
	GenerationID      string    `json:"generationId"`
	ManifestHash      string    `json:"manifestHash"`
	CaptureStartedAt  time.Time `json:"captureStartedAt"`
	CaptureFinishedAt time.Time `json:"captureFinishedAt"`
	ReceivedAt        time.Time `json:"receivedAt"`
	TotalRows         uint32    `json:"totalRows"`
	UnidentifiedRows  uint32    `json:"unidentifiedRows"`
}
type Count struct {
	Name            string `json:"name"`
	ActiveCount     uint32 `json:"activeCount"`
	NonRunningCount uint32 `json:"nonRunningCount"`
}
type Input struct {
	DeviceID, Identity, Epoch, SourceToken string
	AuthorityUntil                         time.Time
	Available                              bool
	Authorized                             bool
	Reason                                 string
	Sample                                 *Generation
	Counts                                 []Count
}
type ConfigureRequest struct {
	ExpectedRevision       uint64
	RequestID, SourceToken string
	Enabled                bool
	Names                  []string
	ConsecutiveFailures    int
	RetentionAcknowledged  bool
}
type AcknowledgeRequest struct {
	ExpectedRevision                   uint64
	RequestID, SourceToken, IncidentID string
}
type Policy struct {
	Enabled             bool       `json:"enabled"`
	Names               []string   `json:"names"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	EnabledAt           *time.Time `json:"enabledAt"`
}
type Observation struct {
	Generation      Generation `json:"generation"`
	ActiveCount     uint32     `json:"activeCount"`
	NonRunningCount uint32     `json:"nonRunningCount"`
}
type Proof struct {
	First   Observation `json:"first"`
	Last    Observation `json:"last"`
	Samples int         `json:"samples"`
}
type Incident struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Identity       string     `json:"identity"`
	State          string     `json:"state"`
	OpenedAt       time.Time  `json:"openedAt"`
	LastObservedAt time.Time  `json:"lastObservedAt"`
	ClosedAt       *time.Time `json:"closedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
	Opening        Proof      `json:"opening"`
	Recovery       *Proof     `json:"recovery"`
}
type Progress struct {
	Name         string       `json:"name"`
	Condition    string       `json:"condition"`
	Last         *Observation `json:"last"`
	FailureFirst *Observation `json:"failureFirst"`
	SuccessFirst *Observation `json:"successFirst"`
	FailureCount int          `json:"failureCount"`
	SuccessCount int          `json:"successCount"`
}
type LastRequest struct {
	RequestID   string  `json:"requestId"`
	Operation   string  `json:"operation"`
	SourceToken string  `json:"sourceToken"`
	IncidentID  *string `json:"incidentId"`
}
type Command struct {
	Public                LastRequest `json:"public"`
	ExpectedRevision      uint64      `json:"expectedRevision"`
	Identity              string      `json:"identity"`
	Epoch                 string      `json:"epoch"`
	Policy                *Policy     `json:"policy"`
	RetentionAcknowledged bool        `json:"retentionAcknowledged"`
}
type State struct {
	DeviceID       string      `json:"deviceId"`
	Identity       string      `json:"identity"`
	Epoch          string      `json:"epoch"`
	ClockFloor     time.Time   `json:"clockFloor"`
	Revision       uint64      `json:"revision"`
	NextID         uint64      `json:"nextId"`
	Policy         Policy      `json:"policy"`
	Progress       []Progress  `json:"progress"`
	Incidents      []Incident  `json:"incidents"`
	EarlierOmitted uint64      `json:"earlierOmitted"`
	LastRequest    *Command    `json:"lastRequest"`
	LastGeneration *Generation `json:"lastGeneration"`
	SeenSequence   uint64      `json:"seenSequence"`
}
type PublicSource struct {
	Token      string      `json:"token"`
	Scope      string      `json:"scope"`
	Status     string      `json:"status"`
	Reason     string      `json:"reason"`
	Generation *Generation `json:"generation"`
}
type PublicPolicy struct {
	Policy
	SourceMatches bool `json:"sourceMatches"`
}
type Check struct {
	Name            string  `json:"name"`
	Condition       string  `json:"condition"`
	ActiveCount     *uint32 `json:"activeCount"`
	NonRunningCount *uint32 `json:"nonRunningCount"`
	FailureCount    int     `json:"failureCount"`
	SuccessCount    int     `json:"successCount"`
}
type PublicIncident struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	State          string     `json:"state"`
	SourceCurrent  bool       `json:"sourceCurrent"`
	OpenedAt       time.Time  `json:"openedAt"`
	LastObservedAt time.Time  `json:"lastObservedAt"`
	ClosedAt       *time.Time `json:"closedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
	Opening        Proof      `json:"opening"`
	Recovery       *Proof     `json:"recovery"`
}
type PublicView struct {
	SchemaVersion  string           `json:"schemaVersion"`
	DeviceID       string           `json:"deviceId"`
	ServerNow      time.Time        `json:"serverNow"`
	ValidUntil     time.Time        `json:"validUntil"`
	Revision       string           `json:"revision"`
	CanManage      bool             `json:"canManage"`
	ClockReliable  bool             `json:"clockReliable"`
	MaxRules       int              `json:"maxRules"`
	MaxIncidents   int              `json:"maxIncidents"`
	RetentionDays  int              `json:"retentionDays"`
	EarlierOmitted uint64           `json:"earlierOmitted"`
	Source         PublicSource     `json:"source"`
	Policy         PublicPolicy     `json:"policy"`
	Checks         []Check          `json:"checks"`
	Incidents      []PublicIncident `json:"incidents"`
	LastRequest    *LastRequest     `json:"lastRequest"`
}
