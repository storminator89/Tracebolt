package native

import "context"

// PrerequisiteObservation is a finite read-only policy result. It deliberately
// does not claim access under the future SCM service token. A blocked descriptor
// means this sufficient policy rejected it, not that LocalService was denied.
type PrerequisiteObservation struct {
	Status string `json:"status"`
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// InspectPrerequisites reads the host layout/filesystem, existing security
// descriptors, administrator elevation and fixed resource absence. It creates
// no service, account, identity, credential, file, ACL, listener or token grant.
// It is the only native entry referenced by the standalone prerequisites command.
func InspectPrerequisites(ctx context.Context) PrerequisiteObservation {
	d := &Driver{evidence: Evidence{Stage: StageIdle, Reason: ReasonNone}, prerequisiteCheck: "platform"}
	defer d.releasePrerequisiteHandles()
	err := d.Preflight(ctx)
	return prerequisiteObservation(d.prerequisiteCheck, d.Evidence().Reason, err)
}
func prerequisiteObservation(check string, reason Reason, err error) PrerequisiteObservation {
	p := PrerequisiteObservation{Status: "unverified", Check: check, Reason: "inspection-failed"}
	if !validPrerequisiteCheck(check) {
		p.Check = "idle"
		return p
	}
	if err == nil && check == "complete" && reason == ReasonNone {
		p.Status = "supported"
		p.Reason = "none"
		return p
	}
	if check == "complete" {
		p.Check = "idle"
		return p
	}
	switch reason {
	case ReasonUnsupported:
		p.Reason = "unsupported-platform"
	case ReasonTimeout:
		p.Reason = "cancelled"
	case ReasonPrerequisite:
		if check != "idle" && check != "platform" {
			p.Status = "blocked"
			p.Reason = "prerequisite-blocked"
		}
	case ReasonExisting:
		if check == "resource-absence" {
			p.Status = "blocked"
			p.Reason = "existing-resource"
		}
	}
	return p
}
func validPrerequisiteCheck(s string) bool {
	switch s {
	case "idle", "platform", "layout", "elevation", "filesystem", "ancestor-policy", "resource-absence", "complete":
		return true
	}
	return false
}

// Valid validates only finite classifications, not any native acceptance claim.
func (p PrerequisiteObservation) Valid() bool {
	if !validPrerequisiteCheck(p.Check) {
		return false
	}
	switch p.Status {
	case "supported":
		return p.Check == "complete" && p.Reason == "none"
	case "blocked":
		if p.Check == "idle" || p.Check == "platform" || p.Check == "complete" {
			return false
		}
		return p.Reason == "prerequisite-blocked" || p.Check == "resource-absence" && p.Reason == "existing-resource"
	case "unverified":
		return p.Check != "complete" && (p.Reason == "unsupported-platform" || p.Reason == "inspection-failed" || p.Reason == "cancelled")
	}
	return false
}
