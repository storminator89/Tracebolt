package applicationcheck

import (
	"context"
	"errors"
	"time"
)

const IncidentSchema = "tracebolt.application-incidents.v1"
const IncidentLimit = 128
const IncidentRetention = 30 * 24 * time.Hour
const IncidentMaxBytes = 196608

var ErrIncidentInvalid = errors.New("application_incident_invalid")
var ErrIncidentUnavailable = errors.New("application_incident_unavailable")

type IncidentTarget struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Scheme *string `json:"targetScheme"`
}

// Key is a private exact-configuration binding. Token is an opaque runtime occurrence,
// never a credential. Neither this descriptor nor its clock is a public wire DTO.
type IncidentSource struct {
	Key, Token, Mode               string
	Enabled                        bool
	IntervalSeconds, MaxAgeSeconds int
	Targets                        []IncidentTarget
	Now                            func() time.Time
}
type IncidentObservation struct {
	TargetID, Kind, Scheme, State, Reason string
	ObservedAt, CompletedAt               time.Time
	HTTPStatus                            *int
}
type IncidentSink interface {
	ObserveApplicationSource(context.Context, IncidentSource) error
	ObserveApplicationResult(context.Context, IncidentSource, IncidentObservation) error
}

type IncidentCommand struct {
	RequestID             string   `json:"requestId"`
	ExpectedRevision      uint64   `json:"expectedRevision,string"`
	Operation             string   `json:"operation"`
	SourceToken           string   `json:"sourceToken"`
	TargetIDs             []string `json:"targetIds"`
	ConsecutiveFailures   int      `json:"consecutiveFailures"`
	IncidentID            *string  `json:"incidentId"`
	RetentionAcknowledged bool     `json:"retentionAcknowledged"`
}
type IncidentOpening struct {
	FirstObservedAt time.Time `json:"firstObservedAt"`
	ObservedAt      time.Time `json:"observedAt"`
	CompletedAt     time.Time `json:"completedAt"`
	Reason          string    `json:"reason"`
	HTTPStatus      *int      `json:"httpStatus"`
	Samples         int       `json:"samples"`
}
type IncidentRecovery struct {
	FirstObservedAt time.Time `json:"firstObservedAt"`
	ObservedAt      time.Time `json:"observedAt"`
	CompletedAt     time.Time `json:"completedAt"`
	Samples         int       `json:"samples"`
}
type ApplicationIncident struct {
	SourceCurrent   bool              `json:"sourceCurrent"`
	ID              string            `json:"id"`
	TargetID        string            `json:"targetId"`
	Kind            string            `json:"kind"`
	Scheme          *string           `json:"targetScheme"`
	State           string            `json:"state"`
	Opening         IncidentOpening   `json:"opening"`
	LastObservedAt  time.Time         `json:"lastObservedAt"`
	LastCompletedAt time.Time         `json:"lastCompletedAt"`
	ClosedAt        *time.Time        `json:"closedAt"`
	AcknowledgedAt  *time.Time        `json:"acknowledgedAt"`
	Recovery        *IncidentRecovery `json:"recovery"`
}
type IncidentCheck struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Scheme       *string    `json:"targetScheme"`
	Condition    string     `json:"condition"`
	ObservedAt   *time.Time `json:"observedAt"`
	CompletedAt  *time.Time `json:"completedAt"`
	Reason       *string    `json:"reason"`
	HTTPStatus   *int       `json:"httpStatus"`
	FailureCount int        `json:"failureCount"`
	SuccessCount int        `json:"successCount"`
}
type IncidentPolicyView struct {
	Enabled             bool       `json:"enabled"`
	SourceMatches       bool       `json:"sourceMatches"`
	TargetIDs           []string   `json:"targetIds"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	EnabledAt           *time.Time `json:"enabledAt"`
}
type IncidentSourceView struct {
	Token           string           `json:"token"`
	Mode            string           `json:"mode"`
	ChecksEnabled   bool             `json:"checksEnabled"`
	IntervalSeconds int              `json:"intervalSeconds"`
	MaxAgeSeconds   int              `json:"maxAgeSeconds"`
	Targets         []IncidentTarget `json:"targets"`
}
type IncidentRequestView struct {
	RequestID   string  `json:"requestId"`
	Operation   string  `json:"operation"`
	SourceToken string  `json:"sourceToken"`
	IncidentID  *string `json:"incidentId"`
}
type IncidentView struct {
	SchemaVersion  string                `json:"schemaVersion"`
	ServerNow      time.Time             `json:"serverNow"`
	Revision       uint64                `json:"revision,string"`
	CanManage      bool                  `json:"canManage"`
	ClockReliable  bool                  `json:"clockReliable"`
	RetentionDays  int                   `json:"retentionDays"`
	MaxIncidents   int                   `json:"maxIncidents"`
	EarlierOmitted bool                  `json:"earlierOmitted"`
	CurrentSource  IncidentSourceView    `json:"currentSource"`
	Policy         IncidentPolicyView    `json:"policy"`
	Checks         []IncidentCheck       `json:"checks"`
	Incidents      []ApplicationIncident `json:"incidents"`
	LastRequest    *IncidentRequestView  `json:"lastRequest"`
}
