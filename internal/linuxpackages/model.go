// Package linuxpackages contains pure, bounded parsers for a proposed Linux
// package observation. It has no collector, command runner, network client,
// frame/transport integration, provenance authority, or CVE/update assessment.
package linuxpackages

// ReleaseFields retains only exact os-release identifiers. A nil value means
// absent; a non-nil empty string means explicitly empty. Neither permits a
// supported-release inference. Display names and ID_LIKE are never retained.
type ReleaseFields struct {
	ID              *string `json:"id"`
	VersionID       *string `json:"versionId"`
	VersionCodename *string `json:"versionCodename"`
}

type ReleaseTarget string

const (
	Debian13     ReleaseTarget = "debian-13-trixie"
	Ubuntu2404   ReleaseTarget = "ubuntu-24.04-noble"
	Unsupported  ReleaseTarget = "unsupported"
	Incomplete   ReleaseTarget = "incomplete"
	Inconsistent ReleaseTarget = "inconsistent"
)

// Target is an exact routing hint, not proof of OS, vendor, repository, artifact
// origin, host namespace, or advisory coverage. Missing facts have no defaults.
func (r ReleaseFields) Target() ReleaseTarget {
	if r.ID == nil || r.VersionID == nil || r.VersionCodename == nil ||
		*r.ID == "" || *r.VersionID == "" || *r.VersionCodename == "" {
		return Incomplete
	}
	switch *r.ID {
	case "debian":
		if *r.VersionID == "13" && *r.VersionCodename == "trixie" {
			return Debian13
		}
		if *r.VersionID == "13" || *r.VersionCodename == "trixie" {
			return Inconsistent
		}
	case "ubuntu":
		if *r.VersionID == "24.04" && *r.VersionCodename == "noble" {
			return Ubuntu2404
		}
		if *r.VersionID == "24.04" || *r.VersionCodename == "noble" {
			return Inconsistent
		}
	}
	return Unsupported
}

// PackageRow is selected local metadata, not authenticated artifact identity.
// The absence of origin fields is intentional. A caller must not upgrade these
// rows into verified-origin assertions or attach a whole-source digest.
type PackageRow struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	SourcePackage string `json:"sourcePackage"`
	SourceVersion string `json:"sourceVersion"`
	SourceMapping string `json:"sourceMapping"`
	InstallState  string `json:"installState"`
}
