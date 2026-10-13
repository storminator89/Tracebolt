//go:build !darwin

package macosinventory

import "context"

func nativeSources() Sources {
	return Sources{
		Hardware:  func(context.Context) (Hardware, error) { return Hardware{}, ErrUnsupported },
		Receipts:  func(context.Context) (Receipts, error) { return Receipts{}, ErrUnsupported },
		Processes: func(context.Context) (Processes, error) { return Processes{}, ErrUnsupported },
		Network:   func(context.Context) (Network, error) { return Network{}, ErrUnsupported },
	}
}
