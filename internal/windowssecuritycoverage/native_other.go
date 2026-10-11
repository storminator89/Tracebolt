//go:build !windows

package windowssecuritycoverage

import "context"

func nativeAntivirus(context.Context) (Antivirus, error) { return Antivirus{}, ErrUnsupported }
func nativeTPM(context.Context) (TPM, error)             { return TPM{}, ErrUnsupported }
