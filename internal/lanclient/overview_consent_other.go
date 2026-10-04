//go:build !linux

package lanclient

func writeOverviewConsent(Material, []byte) error { return ErrConfiguration }
func removeOverviewConsent(Material) error        { return ErrConfiguration }
func overviewInitializationState(Material) error  { return ErrConfiguration }
func beginOverviewInitialization(Material) error  { return ErrConfiguration }
func finishOverviewInitialization(Material) error { return ErrConfiguration }
