//go:build !darwin

package macosinventorysender

// No Linux/Windows filesystem adapter is supplied or claimed for this domain.
func openStorageBackend(string, bool) (storageBackend, error) {
	return nil, ErrStorageUnsupported
}
