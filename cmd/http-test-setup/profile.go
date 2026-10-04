package main

import "localrmm/internal/enrollmentcrypto"

// Only these three immutable layouts can be selected. No caller-supplied path,
// port, existing state or material is accepted by the CLI.
type setupProfile uint8

const (
	basicSetup setupProfile = iota
	inventorySetup
	completeSetup
	basicProfileName         = enrollmentcrypto.CollectionProfile
	inventoryProfileName     = enrollmentcrypto.CollectionProfilePackages
	completeProfileName      = enrollmentcrypto.CollectionProfileComplete
	completeOutputName       = "tracebolt-http-complete-test"
	completeOutputDirectory  = "/etc/" + completeOutputName
	completeStagePrefix      = ".tracebolt-http-complete-test-setup-"
	inventoryOutputName      = "tracebolt-http-inventory-test"
	inventoryOutputDirectory = "/etc/" + inventoryOutputName
	stagePrefix              = ".tracebolt-http-test-setup-"
	inventoryStagePrefix     = ".tracebolt-http-inventory-test-setup-"
)

func selectProfile(name string, acknowledged bool) (setupProfile, error) {
	switch {
	case name == basicProfileName && !acknowledged:
		return basicSetup, nil
	case name == inventoryProfileName && acknowledged:
		return inventorySetup, nil
	case name == completeProfileName && acknowledged:
		return completeSetup, nil
	default:
		return 0, errSetup
	}
}

func (p setupProfile) paths() (directory, name, staging string, err error) {
	switch p {
	case basicSetup:
		return outputDirectory, outputName, stagePrefix, nil
	case inventorySetup:
		return inventoryOutputDirectory, inventoryOutputName, inventoryStagePrefix, nil
	case completeSetup:
		return completeOutputDirectory, completeOutputName, completeStagePrefix, nil
	default:
		return "", "", "", errSetup
	}
}

const inventoryNotice = "Collection profile: managed-operations-v2 (fresh temporary test instance).\nExpanded metadata: volume/mount labels and usage; interface names, state and counters; service unit names/states; process IDs/names/resource usage; package names, installed/source versions, architecture, source mappings and install state; OS release identifiers; event source/unit/priority/message IDs, counts and timestamps.\nMetadata labels and package/source information may be sensitive. HTTP exposes this metadata as well as passwords, sessions and enrollment traffic.\nOld basic configuration/state remain retained unused. A separate project and fresh state volume are required; stop the old test container before publishing the same ports.\n"

const completeNotice = "Collection profile: managed-operations-v3 (fresh temporary complete-dpkg test instance).\nScope: complete supported dpkg package inventory generations with paginated row access; not all software. Unsupported software managers remain unknown. The v3 consent target also includes system service names and active/failed/enablement states; locally observed TCP listeners, UDP-bound sockets and connections with numeric local/remote addresses and ports; and PID/name attribution where permitted, with unavailable values explicitly unknown. Private network topology may be sensitive. No network scans, firewall/namespace/global privilege changes, raw logs, command lines, environment, usernames, payloads or DNS queries. This setup plan declares consent scope, not collector/runtime availability.\nPackage names, installed/source versions, architecture, source mappings, install state, OS release identifiers and existing operational labels may be sensitive. HTTP exposes this metadata, passwords, sessions and enrollment traffic.\nQuotas and source failures produce explicit failed/unavailable results, never a prefix labeled complete. Current and previous generations retain their original observation ages. Rows have at most 24-hour visibility; last-complete bytes can persist after visibility expiry until replaced or eligible cleanup.\nNo AI export is enabled. No CVE or update guarantees are made. Old setups remain retained unused; a separate project, fresh state volume and fresh endpoint identity are required. Stop the old test container before publishing the same ports.\n"
