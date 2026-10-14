//go:build !((darwin && !ios) || (linux && !android))

package main

import "os"

// Unsupported hosts may inspect source, but never open selected package inputs.
// There is no unsafe fallback to a path-following os.Open.
func openSelectedRegular(string, int64) (*os.File, error) { return nil, errRejected }
