//go:build !linux

package lanclient

func loadActionLocal(Material) (actionLocal, error) { return actionLocal{}, errActionDisabled }
