// Package linuxmountwatch evaluates one explicitly selected namespace-local
// mounted-filesystem location from already accepted complete generations.
// It performs no collection, external delivery or endpoint action.
package linuxmountwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxAge = 2 * time.Minute
const Retention = 30 * 24 * time.Hour
const MaxDevices = 25
const MaxOptions = 64
const MaxIncidents = 100
const MaxStateBytes = 128 << 10

var ErrInvalid = errors.New("mount_watch_invalid")
var ErrConflict = errors.New("mount_watch_conflict")
var ErrSource = errors.New("mount_watch_source")

type Target struct {
	MountPoint      string `json:"mountPoint"`
	Filesystem      string `json:"filesystem"`
	FilesystemGroup string `json:"filesystemGroup"`
}
type Sample struct {
	Target
	MountID        string  `json:"mountId"`
	UsedPercent    float64 `json:"usedPercent"`
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
}
type Generation struct {
	Sequence   uint64    `json:"sequence,string"`
	ID         string    `json:"id"`
	CapturedAt time.Time `json:"capturedAt"`
	ReceivedAt time.Time `json:"receivedAt"`
}
type Input struct {
	DeviceID, Identity, SourceToken string
	AuthorityUntil                  time.Time
	Available                       bool
	Reason                          string
	Generation                      *Generation
	Options                         []Target
	MoreOptions                     bool
	Sample                          *Sample
}
type Policy struct {
	Enabled   bool       `json:"enabled"`
	Target    *Target    `json:"target"`
	Threshold int        `json:"threshold"`
	Recovery  int        `json:"recovery"`
	EnabledAt *time.Time `json:"enabledAt"`
}
type Check struct {
	Condition   string     `json:"condition"`
	UsedPercent *float64   `json:"usedPercent"`
	ObservedAt  *time.Time `json:"observedAt"`
	Bad         int        `json:"bad"`
	Good        int        `json:"good"`
	MountID     string     `json:"mountId"`
}
type Incident struct {
	ID             string     `json:"id"`
	Target         Target     `json:"target"`
	State          string     `json:"state"`
	OpenedAt       time.Time  `json:"openedAt"`
	LastObservedAt time.Time  `json:"lastObservedAt"`
	ClosedAt       *time.Time `json:"closedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt"`
}
type Command struct {
	RequestID             string  `json:"requestId"`
	ExpectedRevision      uint64  `json:"expectedRevision,string"`
	SourceToken           string  `json:"sourceToken"`
	Operation             string  `json:"operation"`
	Target                *Target `json:"target"`
	Threshold             int     `json:"threshold"`
	Recovery              int     `json:"recovery"`
	RetentionAcknowledged bool    `json:"retentionAcknowledged"`
	IncidentID            string  `json:"incidentId"`
}
type State struct {
	DeviceID       string      `json:"deviceId"`
	Identity       string      `json:"identity"`
	Revision       uint64      `json:"revision,string"`
	NextID         uint64      `json:"nextId"`
	Policy         Policy      `json:"policy"`
	Check          Check       `json:"check"`
	LastGeneration *Generation `json:"lastGeneration"`
	SeenSequence   uint64      `json:"seenSequence,string"`
	ClockFloor     time.Time   `json:"clockFloor"`
	Incidents      []Incident  `json:"incidents"`
	EarlierOmitted uint64      `json:"earlierOmitted"`
	LastRequest    *Command    `json:"lastRequest"`
}
type View struct {
	SchemaVersion  string      `json:"schemaVersion"`
	DeviceID       string      `json:"deviceId"`
	ServerNow      time.Time   `json:"serverNow"`
	ExpiresAt      time.Time   `json:"expiresAt"`
	SourceToken    string      `json:"sourceToken"`
	SourceStatus   string      `json:"sourceStatus"`
	Revision       uint64      `json:"revision,string"`
	CanManage      bool        `json:"canManage"`
	Policy         Policy      `json:"policy"`
	Check          Check       `json:"check"`
	Generation     *Generation `json:"generation"`
	Options        []Target    `json:"options"`
	MoreOptions    bool        `json:"moreOptions"`
	Incidents      []Incident  `json:"incidents"`
	EarlierOmitted uint64      `json:"earlierOmitted"`
	LastRequest    *Command    `json:"lastRequest"`
}

func validHex(s, p string, n int) bool {
	if len(s) != len(p)+n || !strings.HasPrefix(s, p) {
		return false
	}
	for _, c := range s[len(p):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var filesystemPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var groupPattern = regexp.MustCompile(`^fs_(0|[1-9][0-9]{0,9})_(0|[1-9][0-9]{0,9})$`)

func ValidTarget(t Target) bool {
	if !filesystemPattern.MatchString(t.Filesystem) || !groupPattern.MatchString(t.FilesystemGroup) {
		return false
	}
	for _, p := range strings.Split(strings.TrimPrefix(t.FilesystemGroup, "fs_"), "_") {
		if _, e := strconv.ParseUint(p, 10, 32); e != nil {
			return false
		}
	}
	if t.MountPoint == "/" || len(t.MountPoint) > 4096 || !strings.HasPrefix(t.MountPoint, "/") || path.Clean(t.MountPoint) != t.MountPoint || strings.Contains(t.MountPoint, "[redacted]") || !utf8.ValidString(t.MountPoint) || len(t.Filesystem) < 1 || len(t.Filesystem) > 64 || len(t.FilesystemGroup) < 6 || len(t.FilesystemGroup) > 64 || !strings.HasPrefix(t.FilesystemGroup, "fs_") {
		return false
	}
	for _, c := range t.MountPoint + t.Filesystem + t.FilesystemGroup {
		if unicode.IsControl(c) || unicode.In(c, unicode.Cf) || c == 0x2028 || c == 0x2029 {
			return false
		}
	}
	return true
}
func utc(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func validGeneration(g *Generation) bool {
	return g != nil && g.Sequence > 0 && g.Sequence <= math.MaxInt64 && validHex(g.ID, "sample_", 32) && utc(g.CapturedAt) && utc(g.ReceivedAt) && !g.ReceivedAt.Before(g.CapturedAt)
}
func validInput(in Input, now time.Time) bool {
	return validHex(in.DeviceID, "agent_", 32) && validHex(in.Identity, "", 64) && validHex(in.SourceToken, "mountsource_", 32) && utc(in.AuthorityUntil) && now.Before(in.AuthorityUntil)
}
func fresh(in Input, now time.Time) bool {
	return validInput(in, now) && in.Available && in.Reason == "none" && validGeneration(in.Generation) && !in.Generation.ReceivedAt.After(now) && now.Sub(in.Generation.CapturedAt) < MaxAge && now.Sub(in.Generation.ReceivedAt) < MaxAge
}
func eligible(s *Sample) bool {
	return s != nil && ValidTarget(s.Target) && strings.HasPrefix(s.MountID, "mount_") && s.TotalBytes > 0 && s.TotalBytes <= 1<<53-1 && s.AvailableBytes <= s.TotalBytes && !math.IsNaN(s.UsedPercent) && !math.IsInf(s.UsedPercent, 0) && s.UsedPercent >= 0 && s.UsedPercent <= 100 && math.Abs(s.UsedPercent-float64(s.TotalBytes-s.AvailableBytes)*100/float64(s.TotalBytes)) < 1e-9
}
func New(id string) *State {
	return &State{DeviceID: id, NextID: 1, Check: Check{Condition: "unknown"}, Incidents: []Incident{}}
}
func clone(s *State) *State {
	b, _ := json.Marshal(s)
	var n State
	_ = json.Unmarshal(b, &n)
	return &n
}
func stamp(t time.Time) *time.Time { return &t }
func unknown(s *State)             { s.Check = Check{Condition: "unknown"} }
func retire(s *State, now time.Time) {
	for i := range s.Incidents {
		if s.Incidents[i].State == "open" {
			s.Incidents[i].State = "monitoring_stopped"
			if !now.Before(s.ClockFloor) {
				s.Incidents[i].ClosedAt = stamp(now)
			}
		}
	}
}
func prune(s *State, now time.Time) {
	kept := s.Incidents[:0]
	for _, i := range s.Incidents {
		if i.State != "open" && i.ClosedAt != nil && now.Sub(*i.ClosedAt) > Retention {
			s.EarlierOmitted++
			continue
		}
		kept = append(kept, i)
	}
	s.Incidents = kept
	for {
		raw, e := json.Marshal(s)
		if e != nil {
			return
		}
		if len(s.Incidents) <= MaxIncidents && len(raw) <= MaxStateBytes {
			return
		}
		oldest := -1
		for i, c := range s.Incidents {
			if c.State != "open" && (oldest < 0 || c.LastObservedAt.Before(s.Incidents[oldest].LastObservedAt)) {
				oldest = i
			}
		}
		if oldest < 0 {
			return
		}
		s.Incidents = append(s.Incidents[:oldest], s.Incidents[oldest+1:]...)
		s.EarlierOmitted++
	}
}
func Apply(s *State, in Input, c Command, now time.Time) error {
	if s == nil || !utc(now) || s.DeviceID != in.DeviceID || !validInput(in, now) || !validHex(c.RequestID, "mountrequest_", 32) || c.SourceToken != in.SourceToken {
		return ErrSource
	}
	if s.Identity != "" && s.Identity != in.Identity {
		return ErrSource
	}
	if c.Operation != "enable" && c.Operation != "disable" && c.Operation != "acknowledge" {
		return ErrInvalid
	}
	if c.Operation == "enable" {
		if c.Target == nil || !ValidTarget(*c.Target) || c.Threshold < 50 || c.Threshold > 99 || c.Recovery < 0 || c.Recovery >= c.Threshold || !c.RetentionAcknowledged || c.IncidentID != "" {
			return ErrInvalid
		}
	} else if c.Target != nil || c.Threshold != 0 || c.Recovery != 0 || c.RetentionAcknowledged || c.Operation == "disable" && c.IncidentID != "" || c.Operation == "acknowledge" && !validHex(c.IncidentID, "mountincident_", 16) {
		return ErrInvalid
	}
	if s.Identity == in.Identity && s.LastRequest != nil && reflect.DeepEqual(*s.LastRequest, c) {
		return nil
	}
	if c.ExpectedRevision != s.Revision || s.Revision >= math.MaxInt64 || s.LastRequest != nil && s.LastRequest.RequestID == c.RequestID {
		return ErrConflict
	}
	if now.Before(s.ClockFloor) && c.Operation != "disable" {
		return ErrConflict
	}
	n := clone(s)
	if c.Operation == "enable" {
		if !fresh(in, now) || !eligible(in.Sample) || in.Sample.Target != *c.Target {
			return ErrSource
		}
		retire(n, now)
		n.Policy = Policy{true, c.Target, c.Threshold, c.Recovery, stamp(now)}
		unknown(n)
		n.LastGeneration = in.Generation
	} else if c.Operation == "disable" {
		retire(n, now)
		n.Policy = Policy{}
		unknown(n)
	} else {
		if n.Identity != in.Identity {
			return ErrSource
		}
		found := false
		for i := range n.Incidents {
			if n.Incidents[i].ID == c.IncidentID {
				found = true
				if n.Incidents[i].AcknowledgedAt == nil {
					n.Incidents[i].AcknowledgedAt = stamp(now)
				}
			}
		}
		if !found {
			return ErrInvalid
		}
	}
	if n.Identity != in.Identity {
		n.Incidents = []Incident{}
		n.LastGeneration = in.Generation
	}
	n.Identity = in.Identity
	n.Revision++
	if in.Generation != nil && in.Generation.Sequence > n.SeenSequence {
		n.SeenSequence = in.Generation.Sequence
	}
	n.LastRequest = &c
	if now.After(n.ClockFloor) {
		n.ClockFloor = now
	}
	prune(n, n.ClockFloor)
	*s = *clone(n)
	return nil
}
func Evaluate(s *State, in Input, now time.Time) error {
	if s == nil || !utc(now) || s.DeviceID != in.DeviceID {
		return ErrInvalid
	}
	if !s.Policy.Enabled {
		if s.Revision > 0 && s.Identity == in.Identity && validInput(in, now) && !now.Before(s.ClockFloor) {
			s.ClockFloor = now
			prune(s, now)
		}
		return nil
	}
	if now.Before(s.ClockFloor) {
		unknown(s)
		return nil
	}
	previousClock := s.ClockFloor
	s.ClockFloor = now
	if s.Identity == in.Identity && validInput(in, now) {
		prune(s, now)
	}
	if s.Identity != in.Identity || !fresh(in, now) || !eligible(in.Sample) || s.Policy.Target == nil || in.Sample.Target != *s.Policy.Target {
		unknown(s)
		return nil
	}
	g := in.Generation
	if g.Sequence < s.SeenSequence {
		unknown(s)
		return nil
	}
	if g.Sequence == s.SeenSequence && (s.LastGeneration == nil || g.Sequence != s.LastGeneration.Sequence) {
		unknown(s)
		return nil
	}
	if g.Sequence > s.SeenSequence {
		s.SeenSequence = g.Sequence
	}
	if s.LastGeneration != nil && g.Sequence <= s.LastGeneration.Sequence {
		if g.Sequence < s.LastGeneration.Sequence || g.ID != s.LastGeneration.ID || !g.CapturedAt.Equal(s.LastGeneration.CapturedAt) || !g.ReceivedAt.Equal(s.LastGeneration.ReceivedAt) {
			unknown(s)
		}
		return nil
	}
	if s.LastGeneration != nil && (!g.CapturedAt.After(s.LastGeneration.CapturedAt) || !g.ReceivedAt.After(s.LastGeneration.ReceivedAt)) {
		unknown(s)
		return nil
	}
	advancing := s.LastGeneration != nil && g.CapturedAt.After(s.LastGeneration.CapturedAt) && g.ReceivedAt.After(s.LastGeneration.ReceivedAt) && g.CapturedAt.Sub(s.LastGeneration.CapturedAt) <= MaxAge && now.Sub(previousClock) <= MaxAge
	copyGeneration := *g
	s.LastGeneration = &copyGeneration
	if !advancing || s.Check.MountID != in.Sample.MountID {
		unknown(s)
	}
	s.Check.MountID = in.Sample.MountID
	s.Check.ObservedAt = stamp(g.CapturedAt)
	value := in.Sample.UsedPercent
	s.Check.UsedPercent = &value
	open := -1
	for i, c := range s.Incidents {
		if c.State == "open" {
			open = i
		}
	}
	if value >= float64(s.Policy.Threshold) {
		s.Check.Good = 0
		s.Check.Bad++
		if s.Check.Bad > 2 {
			s.Check.Bad = 2
		}
		s.Check.Condition = "pending"
		if open >= 0 {
			s.Check.Condition = "open"
			s.Incidents[open].LastObservedAt = g.CapturedAt
		} else if s.Check.Bad >= 2 {
			if s.NextID >= math.MaxInt64 {
				return ErrConflict
			}
			s.Incidents = append(s.Incidents, Incident{ID: fmt.Sprintf("mountincident_%016x", s.NextID), Target: *s.Policy.Target, State: "open", OpenedAt: g.CapturedAt, LastObservedAt: g.CapturedAt})
			s.NextID++
			s.Check.Condition = "open"
		}
	} else if value <= float64(s.Policy.Recovery) {
		s.Check.Bad = 0
		s.Check.Good++
		if s.Check.Good > 2 {
			s.Check.Good = 2
		}
		s.Check.Condition = "clear"
		if open >= 0 {
			s.Check.Condition = "recovering"
			s.Incidents[open].LastObservedAt = g.CapturedAt
			if s.Check.Good >= 2 {
				s.Incidents[open].State = "recovered"
				s.Incidents[open].ClosedAt = stamp(g.CapturedAt)
				s.Check.Condition = "clear"
			}
		}
	} else {
		s.Check.Bad = 0
		s.Check.Good = 0
		s.Check.Condition = "clear"
		if open >= 0 {
			s.Check.Condition = "open"
			s.Incidents[open].LastObservedAt = g.CapturedAt
		}
	}
	prune(s, now)
	return nil
}
func Public(s *State, in Input, now time.Time, manage bool) View {
	n := clone(s)
	status := in.Reason
	if !fresh(in, now) {
		unknown(n)
		if status == "none" {
			status = "stale"
		}
	}
	if n.Identity != "" && n.Identity != in.Identity {
		n = New(in.DeviceID)
		status = "identity_changed"
		manage = false
	}
	if now.Before(n.ClockFloor) {
		unknown(n)
		status = "clock_uncertain"
		manage = false
	}
	if n.Policy.Enabled && (!eligible(in.Sample) || n.Policy.Target == nil || in.Sample.Target != *n.Policy.Target || n.LastGeneration == nil || in.Generation == nil || *n.LastGeneration != *in.Generation || n.Check.MountID != in.Sample.MountID) {
		unknown(n)
	}
	if n.Check.ObservedAt == nil || now.Sub(*n.Check.ObservedAt) >= MaxAge {
		unknown(n)
	}
	expires := now.Add(MaxAge)
	if in.AuthorityUntil.Before(expires) {
		expires = in.AuthorityUntil
	}
	if fresh(in, now) && in.Generation.CapturedAt.Add(MaxAge).Before(expires) {
		expires = in.Generation.CapturedAt.Add(MaxAge)
	}
	if n.Check.ObservedAt != nil && n.Check.ObservedAt.Add(MaxAge).Before(expires) {
		expires = n.Check.ObservedAt.Add(MaxAge)
	}
	options := in.Options
	moreOptions := in.MoreOptions
	generation := in.Generation
	if options == nil {
		options = []Target{}
	}
	// A diagnostic response must not advertise current source choices or a
	// generation whose identity or clock is no longer authoritative.
	if status != "none" {
		options = []Target{}
		moreOptions = false
		generation = nil
	}
	return View{"tracebolt.linux-mount-watch.v1", in.DeviceID, now, expires, in.SourceToken, status, n.Revision, manage && validInput(in, now), n.Policy, n.Check, generation, options, moreOptions, n.Incidents, n.EarlierOmitted, n.LastRequest}
}
func Encode(s *State) ([]byte, error) {
	if Validate(s) != nil {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(s)
	if e != nil || len(b) > MaxStateBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func Decode(b []byte) (*State, error) {
	if len(b) == 0 || len(b) > MaxStateBytes {
		return nil, ErrInvalid
	}
	var s State
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || Validate(&s) != nil {
		return nil, ErrInvalid
	}
	canonical, _ := json.Marshal(&s)
	if !bytes.Equal(canonical, b) {
		return nil, ErrInvalid
	}
	return &s, nil
}
func Validate(s *State) error {
	if s == nil || !validHex(s.DeviceID, "agent_", 32) || s.NextID < 1 || s.NextID > math.MaxInt64 || s.Revision > math.MaxInt64 || s.SeenSequence > math.MaxInt64 || len(s.Incidents) > MaxIncidents || s.Incidents == nil {
		return ErrInvalid
	}
	if s.Revision == 0 {
		if s.Identity != "" || s.LastRequest != nil || s.Policy.Enabled || len(s.Incidents) > 0 {
			return ErrInvalid
		}
	} else if !validHex(s.Identity, "", 64) || s.LastRequest == nil || !utc(s.ClockFloor) {
		return ErrInvalid
	}
	if s.Policy.Enabled {
		if s.Policy.Target == nil || !ValidTarget(*s.Policy.Target) || s.Policy.Threshold < 50 || s.Policy.Threshold > 99 || s.Policy.Recovery < 0 || s.Policy.Recovery >= s.Policy.Threshold || s.Policy.EnabledAt == nil || !utc(*s.Policy.EnabledAt) {
			return ErrInvalid
		}
	} else if s.Policy.Target != nil || s.Policy.Threshold != 0 || s.Policy.Recovery != 0 || s.Policy.EnabledAt != nil {
		return ErrInvalid
	}
	if s.LastRequest != nil {
		c := s.LastRequest
		if !validHex(c.RequestID, "mountrequest_", 32) || !validHex(c.SourceToken, "mountsource_", 32) || c.ExpectedRevision >= math.MaxInt64 || c.ExpectedRevision+1 != s.Revision {
			return ErrInvalid
		}
		switch c.Operation {
		case "enable":
			if !s.Policy.Enabled || c.Target == nil || s.Policy.Target == nil || *c.Target != *s.Policy.Target || c.Threshold != s.Policy.Threshold || c.Recovery != s.Policy.Recovery || !c.RetentionAcknowledged || c.IncidentID != "" {
				return ErrInvalid
			}
		case "disable":
			if s.Policy.Enabled || c.Target != nil || c.Threshold != 0 || c.Recovery != 0 || c.RetentionAcknowledged || c.IncidentID != "" {
				return ErrInvalid
			}
		case "acknowledge":
			if c.Target != nil || c.Threshold != 0 || c.Recovery != 0 || c.RetentionAcknowledged || !validHex(c.IncidentID, "mountincident_", 16) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if s.LastGeneration != nil && (!validGeneration(s.LastGeneration) || s.LastGeneration.Sequence > s.SeenSequence) {
		return ErrInvalid
	}
	if s.Check.Bad < 0 || s.Check.Bad > 2 || s.Check.Good < 0 || s.Check.Good > 2 {
		return ErrInvalid
	}
	switch s.Check.Condition {
	case "unknown":
		if s.Check.UsedPercent != nil || s.Check.ObservedAt != nil || s.Check.Bad != 0 || s.Check.Good != 0 || s.Check.MountID != "" {
			return ErrInvalid
		}
	case "clear", "pending", "open", "recovering":
		if s.Check.UsedPercent == nil || math.IsNaN(*s.Check.UsedPercent) || math.IsInf(*s.Check.UsedPercent, 0) || *s.Check.UsedPercent < 0 || *s.Check.UsedPercent > 100 || s.Check.ObservedAt == nil || !utc(*s.Check.ObservedAt) || !strings.HasPrefix(s.Check.MountID, "mount_") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	seen := map[string]bool{}
	open := 0
	for _, i := range s.Incidents {
		if !validHex(i.ID, "mountincident_", 16) || seen[i.ID] || !ValidTarget(i.Target) || !utc(i.OpenedAt) || !utc(i.LastObservedAt) || i.LastObservedAt.Before(i.OpenedAt) || i.ClosedAt != nil && (!utc(*i.ClosedAt) || i.ClosedAt.Before(i.OpenedAt)) || i.AcknowledgedAt != nil && (!utc(*i.AcknowledgedAt) || i.AcknowledgedAt.Before(i.OpenedAt)) {
			return ErrInvalid
		}
		seen[i.ID] = true
		switch i.State {
		case "open":
			open++
			if i.ClosedAt != nil {
				return ErrInvalid
			}
		case "recovered":
			if i.ClosedAt == nil {
				return ErrInvalid
			}
		case "monitoring_stopped":
		default:
			return ErrInvalid
		}
	}
	if open > 0 && !s.Policy.Enabled {
		return ErrInvalid
	}
	if open > 1 {
		return ErrInvalid
	}
	return nil
}

// Interrupt removes confidence only; historical incidents and source watermarks
// remain intact until a later authorized evaluation supplies new evidence.
func Interrupt(s *State) {
	if s != nil {
		unknown(s)
	}
}
