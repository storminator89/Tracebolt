//go:build !linux

package lanclient

func writeEndpointConsent(Material, []byte) error { return ErrConfiguration }
func removeEndpointConsent(Material) error        { return ErrConfiguration }
