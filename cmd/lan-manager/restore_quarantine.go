package main

import (
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
)

// Parse configuration first, but deny restored state before loading any key,
// verifier, issuer, optional delivery setting or runtime store.
func loadStartupMaterial(path string) (lanconfig.Material, error) {
	config, err := lanconfig.LoadConfig(path)
	if err != nil {
		return lanconfig.Material{}, err
	}
	if err = lanstore.CheckRestoreQuarantine(config.StateDirectory); err != nil {
		return lanconfig.Material{}, err
	}
	return lanconfig.LoadMaterial(config)
}
