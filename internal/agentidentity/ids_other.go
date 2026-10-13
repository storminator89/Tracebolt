//go:build !linux && !darwin

package agentidentity

func serviceProcessIDs(int, int) bool { return false }
