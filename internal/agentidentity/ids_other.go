//go:build !linux

package agentidentity

func serviceProcessIDs(int, int) bool { return false }
