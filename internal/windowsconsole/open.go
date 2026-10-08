package windowsconsole

// openVerifiedConsole is the native open sequence with inert operation seams.
// There are no additional probes: resolve the fixed API, open the fixed device,
// check its type, and close it on type rejection, in exactly that order.
func openVerifiedConsole(resolve func() error, open func() (console, error), characterDevice func(console) (bool, error)) (console, error) {
	if resolve() != nil {
		return nil, failure(CategoryResolve)
	}
	c, err := open()
	if err != nil || c == nil {
		return nil, failure(CategoryOpen)
	}
	character, err := characterDevice(c)
	if err != nil || !character {
		if c.close() != nil {
			return nil, failure(CategoryClose)
		}
		return nil, failure(CategoryType)
	}
	return c, nil
}
