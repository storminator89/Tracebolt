// Package windowsresource binds independent CPU and physical-memory policies to
// the existing percentage-evidence engine. It never grants collection or exports
// observations to Linux Health, AI, alarms or service actions.
package windowsresource

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"localrmm/internal/model"
	"localrmm/internal/windowscapacity"
)

type Kind string

const (
	CPU           Kind = "cpu"
	Memory        Kind = "memory"
	SchemaVersion      = "tracebolt.windows-resource-view.v1"
	MaxStateBytes      = windowscapacity.MaxStateBytes
)

func ValidKind(kind Kind) bool { return kind == CPU || kind == Memory }

// State is a separate, canonical tagged envelope. Disk state cannot decode as a
// resource state. Each metric owns its policy, history and durable evidence floors.
// Engine incident IDs are local to (device, metric), never global identities.
type State struct {
	Version    int                   `json:"version"`
	Metric     Kind                  `json:"metric"`
	Assessment windowscapacity.State `json:"assessment"`
}

type View struct {
	windowscapacity.View
	Metric Kind `json:"metric"`
}

func New(kind Kind) State { return State{Version: 1, Metric: kind, Assessment: windowscapacity.New()} }
func (s State) Validate(kind Kind) error {
	if s.Version != 1 || !ValidKind(kind) || s.Metric != kind || s.Assessment.Validate() != nil {
		return windowscapacity.ErrInvalid
	}
	return nil
}

// Select is the only percentage-slot adapter. The historical engine's Disk slot
// is not a scope grant: callers must first validate the independent resource tag.
// Missing/partial CPU or RAM is passed unchanged; disk is never a fallback.
func Select(in windowscapacity.Input, kind Kind) (windowscapacity.Input, error) {
	var metric model.Metric
	switch kind {
	case CPU:
		metric = in.CPU
	case Memory:
		metric = in.Memory
	default:
		return windowscapacity.Input{}, windowscapacity.ErrInvalid
	}
	return windowscapacity.Input{Input: in.Input, Disk: metric}, nil
}
func (s *State) Configure(in windowscapacity.Input, kind Kind, enabled bool, threshold int, expected uint64, now time.Time) error {
	if err := s.Validate(kind); err != nil {
		return err
	}
	selected, err := Select(in, kind)
	if err != nil {
		return err
	}
	return s.Assessment.Configure(selected, enabled, threshold, expected, now)
}
func (s *State) Evaluate(in windowscapacity.Input, kind Kind, now time.Time, epoch string) error {
	if err := s.Validate(kind); err != nil {
		return err
	}
	selected, err := Select(in, kind)
	if err != nil {
		return err
	}
	return s.Assessment.Evaluate(selected, now, epoch)
}
func MakeView(state windowscapacity.State, in windowscapacity.Input, kind Kind, now time.Time, epoch string) (View, error) {
	selected, err := Select(in, kind)
	if err != nil {
		return View{}, err
	}
	view := state.View(selected, now, epoch)
	view.SchemaVersion = SchemaVersion
	return View{View: view, Metric: kind}, nil
}
func Encode(s State) ([]byte, error) {
	if err := s.Validate(s.Metric); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxStateBytes {
		return nil, windowscapacity.ErrInvalid
	}
	return raw, nil
}
func Decode(raw []byte, kind Kind) (State, error) {
	if len(raw) == 0 || len(raw) > MaxStateBytes || !ValidKind(kind) {
		return State{}, windowscapacity.ErrInvalid
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Validate(kind) != nil {
		return State{}, windowscapacity.ErrInvalid
	}
	canonical, err := Encode(state)
	if err != nil || !bytes.Equal(raw, canonical) {
		return State{}, windowscapacity.ErrInvalid
	}
	return state, nil
}
