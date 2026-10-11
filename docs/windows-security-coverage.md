# Windows Security Center antivirus and TPM context

Source-only candidate, 11 October 2026. The private Security view adds genuine
Windows Security Center registered antivirus product metadata and public TPM
Base Services device presence/version to the separate Defender/Firewall view.
It does not establish overall protection, compliance, TPM readiness, ownership,
attestation, or BitLocker protection. No native host read has been performed.

## Exact fresh approval

`windows-security-coverage-v1` is a new default-off local scope. Fresh Read admin
uses consent v8 with fifteen exact scopes and outer receipt 6. Historical
consent v1–v7, receipts, worker modes and five-scope Setup remain unchanged;
none authorize the new scope. The fresh installer checks the exact public
`/v1/windows/read-admin-setup-capabilities-v4` advertisement and
`fresh-fifteen-read-admin-scopes-v1` contract before enrollment.

The existing identity-bound create-only consent coordinator discloses antivirus
product names/status and TPM presence/version. HTTP-test has an additional
plaintext warning. It verifies the same limited LocalService identity, stopped
owned service and all protected phase/identity/grant records. A separate
`-security-coverage` protected sibling owns this grant. No ACL, account, provider,
privilege, network, authentication, service-action or remediation change occurs.
The source interfaces are not permission to install, enable grants or read a host.

## Documented read-only sources

Antivirus uses fixed local `CLSID_WSCProductList`, initialized once for
`WSC_SECURITY_PROVIDER_ANTIVIRUS`, and the `Count` and indexed `Item` getters.
Each `IWscProduct` supplies only `ProductName`, `ProductState` and
`SignatureStatus`. The Windows SDK interfaces inherit `IDispatch`; the native
adapter uses bounded automation values. There is no undocumented SecurityCenter2
`productState` bit decoding. Registered products can include Microsoft Defender
and third-party products; no provider is identified by guessing its name.

The native OS product type explicitly gates this documented client-only API:
Windows Server yields unsupported, never an empty antivirus list. A successfully
read empty list means no products reported by this source, not no antivirus
software or no protection. States are on/off/snoozed/expired/unknown, and reported
signature status is up-to-date/out-of-date/unknown. These are provider reports,
not independent security verification. Unknown enums and failed getters preserve
unknowns and partial quality. Product names are bounded to 128 UTF-16 units and
reject control/bidirectional-control labels. Counts above 65,535 are rejected;
at most 16 rows are copied. Missing rows retain the original count and truncation.
Remediation paths, GUIDs, timestamps, default-product changes and actions are
never requested. COM activation runs on a locked High/System integrity thread
without impersonation or token/authentication changes; denial stays explicit.

TPM uses only `Tbsi_GetDeviceInfo` with the fixed 16-byte `TPM_DEVICE_INFO`
structure. `TPM_VERSION_12`/`TPM_VERSION_20` map to 1.2/2.0; unfamiliar values
preserve observed presence with unknown version. `TBS_E_TPM_NOT_FOUND` means no
supported TPM was found. Other failures do not become absence. Microsoft labels
`tpmInterfaceType` and `tpmImpRevision` reserved: neither is interpreted or sent.
No TPM context, command, raw state, owner authorization, readiness, ownership,
attestation or provisioning API is used.

BitLocker remains explicitly unavailable in this profile. Microsoft's
`Win32_EncryptableVolume` methods require administrator privileges and an
encrypted provider connection. This increment does not expand LocalService
privileges or change provider/namespace access to obtain it, nor substitute
filesystem encryption support or TPM presence for BitLocker protection.

Primary references:
- [IWSCProductList](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproductlist)
- [Initialize provider semantics](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nf-iwscapi-iwscproductlist-initialize)
- [IWscProduct getters](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproduct)
- [Microsoft Windows SDK interface definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/iwscapi.h)
- [Tbsi_GetDeviceInfo](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo)
- [TPM_DEVICE_INFO reserved fields](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info)
- [BitLocker provider security requirements](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume)

## Bounds, authority and retention

Antivirus and TPM execute in independent fixed current-executable worker modes,
each bounded to two seconds with inherited-pipe wait limited to 100 ms. Before
and after capture, each child authenticates the actual installed SCM parent,
creation time, protected executable hash, activated identity/configuration and
exact current consent. Parent loss has the existing independent watchdog; the
parent kills and reaps timed-out workers. No abandoned native goroutine or raw
provider-error prose is retained. Provider-service internals are outside the
owned worker process bound.

The scope uses the existing five-second optional budget, alternating fair source
priority and three-second primary-delivery reserve. Wire v14 requires
`windowsSecurityCoverage`; older independently granted siblings remain optional.
All old wire shapes and pending retry bytes remain exact. The snapshot is at most
8 KiB and uses the base generation/original conservative capture time. Frame
fitting drops whole optional rows before reaching the 72 KiB frame maximum;
base rows, self metrics, original count/age/grant and source-quality truth remain.
The sender rechecks the current identity and exact grant after capture and before
send/retry; replacement/revocation cannot reuse pending private results.

Only the authenticated operator Windows inventory response contains this data.
Previous useful context keeps its own source time alongside a newer unavailable
attempt; unknown-only provider failures never refresh it. Current scope absence,
grant replacement, terminated identity, response-time authorization and original
24-hour expiry remove private access. The historical bounded retention table
contract remains unchanged; oldest whole captures may be evicted for space.
No public/basic observation, external-AI packet, health policy, alarm, notification
or export receives this scope.

## Verification boundary

Portable fixtures and Windows amd64/arm64 cross-compilation are source evidence,
not actual provider visibility. The separate authorized disposable-Windows gate
must establish client WSC visibility under LocalService, absent/disabled/denied
and third-party AV combinations, Windows Server unsupported behavior, TPM/no-TPM
and unknown versions, provider timeouts, fresh consent/revocation and native
provider-to-manager-to-browser flow. This candidate grants none of those host
reads or installation actions. No released artifact is changed by these tests.
