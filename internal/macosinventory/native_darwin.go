//go:build darwin

package macosinventory

func nativeSources() Sources { return commandSources(runFixedCommand) }
