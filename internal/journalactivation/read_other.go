//go:build !linux

package journalactivation

func Read() (Record, bool, string, error) { return Record{}, false, "", ErrInvalid }
