package windowsfullsoftware

import "time"

const FleetHistoryPageVersion = "tracebolt.windows-fleet-software-history-page.v1"

// This is a private projection of existing history, not a monitor or an export.
type FleetHistoryItem struct {
	DeviceID       string      `json:"deviceId"`
	Identity       string      `json:"identity"`
	AuthorityUntil time.Time   `json:"authorityUntil"`
	History        HistoryPage `json:"history"`
	DetailCursor   string      `json:"detailCursor"`
}
type FleetHistoryPage struct {
	SchemaVersion   string             `json:"schemaVersion"`
	ServerNow       time.Time          `json:"serverNow"`
	Status          string             `json:"status"`
	Search          string             `json:"search"`
	Mode            string             `json:"mode"`
	TotalDevices    int                `json:"totalDevices"`
	Offset          int                `json:"offset"`
	Items           []FleetHistoryItem `json:"items"`
	NextCursor      string             `json:"nextCursor"`
	CursorExpiresAt *time.Time         `json:"cursorExpiresAt"`
	RosterDigest    string             `json:"-"`
	SessionID       string             `json:"-"`
}
