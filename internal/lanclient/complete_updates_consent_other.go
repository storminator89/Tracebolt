//go:build !linux

package lanclient

func writeCompleteUpdatesConsent(Material, []byte) error { return ErrConfiguration }
func removeCompleteUpdatesConsent(Material) error        { return ErrConfiguration }
func completeUpdatesInitializationState(Material) error  { return ErrConfiguration }
func beginCompleteUpdatesInitialization(Material) error  { return ErrConfiguration }
func finishCompleteUpdatesInitialization(Material) error { return ErrConfiguration }
