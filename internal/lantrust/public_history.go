package lantrust

import "time"

// ValidateServerTrustAt checks only server-name syntax and public CA material at
// the supplied instant. Without a server leaf it cannot check a SAN/hostname
// match or an actual TLS connection. It returns no TLS config, certificate pool
// or network-capable object, and does not authenticate the manager or CA.
// Live transports must continue to use ServerTLSConfig and the real clock.
func ValidateServerTrustAt(serverCAPEM []byte, serverName string, at time.Time) error {
	if at.IsZero() || !validServerName(serverName) {
		return ErrConfiguration
	}
	_, err := certificatePool(serverCAPEM, at.UTC())
	return err
}
