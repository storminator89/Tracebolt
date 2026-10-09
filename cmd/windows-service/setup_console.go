package main

import "context"

// Only Ctrl+C and Ctrl+Break can be handled as cooperative cancellation. Windows
// may terminate the process on close/logoff/shutdown regardless of a handler's
// return, so those events must never be presented as clean Setup completion.
type setupConsoleControl struct{ cancel context.CancelFunc }

func (c *setupConsoleControl) handle(event uint32) bool {
	if c == nil || c.cancel == nil || (event != 0 && event != 1) {
		return false
	}
	c.cancel()
	return true
}
