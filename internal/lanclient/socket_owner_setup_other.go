//go:build !linux

package lanclient

func inspectSocketSetupConsent(Material) (*SocketOwnerConsent, error) { return nil, ErrConfiguration }
func openSocketSetupState(Material) (socketSetupState, error)         { return nil, ErrConfiguration }
func writeSocketSetupConsent(Material, *SocketOwnerConsent, SocketOwnerConsent, func() error) error {
	return ErrConfiguration
}
