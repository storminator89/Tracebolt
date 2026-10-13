package windowsfullsoftware

import "time"

const (
	FleetPageVersion    = "tracebolt.windows-fleet-software-page.v1"
	FleetDeviceLimit    = 25
	FleetPageDevices    = 5
	FleetPreviewRows    = 3
	FleetDetailRows     = 20
	FleetCursorLifetime = 5 * time.Minute
)

// FleetQuery is a private, read-only request. Version is literal reported text,
// never a semantic version, upgrade decision or installation predicate.
type FleetQuery struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Cursor  string `json:"cursor"`
}

func ValidateFleetQuery(q FleetQuery) error {
	if q.Name == "" && q.Version == "" {
		return ErrInvalid
	}
	for _, value := range []string{q.Name, q.Version} {
		if ValidateQuery(Query{Search: value, Sort: "name-asc", Limit: 1, Cursor: q.Cursor}) != nil {
			return ErrInvalid
		}
	}
	return nil
}

type FleetItem struct {
	DeviceID       string    `json:"deviceId"`
	Identity       string    `json:"identity"`
	Status         string    `json:"status"`
	AuthorityUntil time.Time `json:"authorityUntil"`
	Complete       *Complete `json:"complete"`
	LatestAttempt  *Attempt  `json:"latestAttempt"`
	MatchingCount  int       `json:"matchingCount"`
	UnknownCount   int       `json:"unknownCount"`
	Rows           []Row     `json:"rows"`
	DetailCursor   string    `json:"detailCursor"`
}

type FleetPage struct {
	SchemaVersion   string      `json:"schemaVersion"`
	ServerNow       time.Time   `json:"serverNow"`
	Status          string      `json:"status"`
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	Mode            string      `json:"mode"`
	TotalDevices    int         `json:"totalDevices"`
	Offset          int         `json:"offset"`
	Items           []FleetItem `json:"items"`
	NextCursor      string      `json:"nextCursor"`
	CursorExpiresAt *time.Time  `json:"cursorExpiresAt"`
	// Server-only guards survive preparation and are never accepted from JSON.
	RosterDigest string `json:"-"`
	SessionID    string `json:"-"`
}
