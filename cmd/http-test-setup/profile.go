package main

import "localrmm/internal/enrollmentcrypto"

// Only these two immutable layouts can be selected. No caller-supplied path,
// port, existing state or material is accepted by the CLI.
type setupProfile uint8

const (
	basicSetup setupProfile = iota
	inventorySetup
	basicProfileName         = enrollmentcrypto.CollectionProfile
	inventoryProfileName     = enrollmentcrypto.CollectionProfilePackages
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
	default:
		return "", "", "", errSetup
	}
}

const inventoryNotice = "Collection profile: managed-operations-v2 (fresh temporary test instance).\nExpanded metadata: volume/mount labels and usage; interface names, state and counters; service unit names/states; process IDs/names/resource usage; package names, installed/source versions, architecture, source mappings and install state; OS release identifiers; event source/unit/priority/message IDs, counts and timestamps.\nMetadata labels and package/source information may be sensitive. HTTP exposes this metadata as well as passwords, sessions and enrollment traffic.\nOld basic configuration/state remain retained unused. A separate project and fresh state volume are required; stop the old test container before publishing the same ports.\n"
