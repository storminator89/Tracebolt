package agentinstall

const readyInstallationVersion = "tracebolt.agent-installation.v1"
const pendingInstallationVersion = "tracebolt.agent-installation.v2"
const readyOwnershipVersion = "tracebolt.agent-install-owner.v1"
const pendingOwnershipVersion = "tracebolt.agent-install-owner.v2"
const readyTransactionVersion = "tracebolt.agent-install-transaction.v1"
const pendingTransactionVersion = "tracebolt.agent-install-transaction.v2"

func validInstallationVersion(version string) bool {
	return version == readyInstallationVersion || version == pendingInstallationVersion
}
func ownerVersion(version string) string {
	if version == pendingInstallationVersion {
		return pendingOwnershipVersion
	}
	return readyOwnershipVersion
}
func transactionVersion(version string) string {
	if version == pendingInstallationVersion {
		return pendingTransactionVersion
	}
	return readyTransactionVersion
}
