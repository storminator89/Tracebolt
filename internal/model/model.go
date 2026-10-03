// Package model defines the versioned, provenance-aware local MVP contract.
package model

import "time"

const Version = "0.1.0"

type Metric struct {
	Value       *float64  `json:"value"`
	Unit        string    `json:"unit"`
	Quality     string    `json:"quality"`
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collectedAt"`
}
type Capability struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type Evidence struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Source      string    `json:"source"`
	Quality     string    `json:"quality"`
	CollectedAt time.Time `json:"collectedAt"`
	Detail      string    `json:"detail"`
	Value       string    `json:"value"`
	Synthetic   bool      `json:"synthetic"`
}
type Device struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Platform     string       `json:"platform"`
	OS           string       `json:"os"`
	Site         string       `json:"site"`
	Group        string       `json:"group"`
	IP           *string      `json:"ip"`
	Status       string       `json:"status"`
	Source       string       `json:"source"`
	Synthetic    bool         `json:"synthetic"`
	LastSeen     time.Time    `json:"lastSeen"`
	AgentVersion string       `json:"agentVersion"`
	CPU          Metric       `json:"cpu"`
	Memory       Metric       `json:"memory"`
	Disk         Metric       `json:"disk"`
	Uptime       string       `json:"uptime"`
	Tags         []string     `json:"tags"`
	Capabilities []Capability `json:"capabilities"`
	Evidence     []Evidence   `json:"evidence"`
	Trend        []float64    `json:"trend"`
	CaseIDs      []string     `json:"caseIds"`
}
type Activity struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Time     time.Time `json:"time"`
	DeviceID string    `json:"deviceId,omitempty"`
	CaseID   string    `json:"caseId,omitempty"`
}
type Note struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"createdAt"`
	Author    string    `json:"author"`
}
type Case struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	DeviceID    string     `json:"deviceId"`
	DeviceName  string     `json:"deviceName"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Category    string     `json:"category"`
	Summary     string     `json:"summary"`
	RuleID      string     `json:"ruleId"`
	Confidence  string     `json:"confidence"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	EvidenceIDs []string   `json:"evidenceIds"`
	Evidence    []Evidence `json:"evidence"`
	RunbookID   string     `json:"runbookId"`
	NextSteps   []string   `json:"nextSteps"`
	Timeline    []Activity `json:"timeline"`
	Notes       []Note     `json:"notes"`
	Synthetic   bool       `json:"synthetic"`
}
type Runbook struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	ReadOnly    bool     `json:"readOnly"`
}
type Stats struct {
	TotalDevices     int `json:"totalDevices"`
	HealthyDevices   int `json:"healthyDevices"`
	AttentionDevices int `json:"attentionDevices"`
	UnknownDevices   int `json:"unknownDevices"`
	OpenCases        int `json:"openCases"`
	CriticalCases    int `json:"criticalCases"`
}
type Overview struct {
	Product     string     `json:"product"`
	Mode        string     `json:"mode"`
	GeneratedAt time.Time  `json:"generatedAt"`
	Stats       Stats      `json:"stats"`
	Devices     []Device   `json:"devices"`
	Cases       []Case     `json:"cases"`
	Activity    []Activity `json:"activity"`
}
