package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"reflect"
)

// readAdminSetupConsent retains the historical twelve-scope development CLI
// and receipt3 contract. It is not the fresh GUI profile.
func readAdminSetupConsent(insecure bool) lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV5, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: lanclient.WindowsReadAdminScopes(), Acknowledged: true, InsecureHTTPAcknowledged: insecure}
}

// freshReadAdminSetupConsent is selected only after the fresh GUI
// acknowledgement and exact transport-risk choice.
func freshReadAdminSetupConsent(insecure bool) lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV14, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: lanclient.WindowsReadAdminScopesV14(), Acknowledged: true, InsecureHTTPAcknowledged: insecure}
}

const setupWizardReadAdminHTTPRiskSummary = "HTTP test only: the invitation and selected telemetry, including identifying physical chassis and BIOS serial metadata, drive letters, volume GUIDs and storage-provider device identifiers/friendly labels, antivirus product names/status, TPM presence/version, personal user/domain/session labels, and complete process PID/parent PID/executable-name/thread-count metadata, local route prefix/next-hop/index/metric/protocol/origin, interface aliases and raw octet/error/discard counters, CPU model/architecture and source-labeled processor counts, installed SMBIOS RAM and OS-usable RAM, system commit current/limit and remaining capacity, and aggregate pagefile allocated/in-use capacity, plus aggregate local PerfDisk (_Total) read/write throughput, operations per second, latency, queue lengths and the measured sample window, on-demand Application/System historical headers and selected historical event-message text that may contain credentials, personal information and other secrets, and complete HKLM software generations used for separately approved manager software-change history travel in plaintext. History compares complete comparable generations for observed registration add/remove and field/version differences with seven-day original-observation retention from the earlier capture, at most 1024 change rows / 1 MiB per device and visible quota gaps. It records no actual install times, upgrade inference or application identity across reinstalls; operator search/paging only, no AI/export/health/actions. Manager responses can be forged. Use an isolated disposable LAN and explicitly accept this separate risk. HTTPS remains the default."

func setupWizardReadAdminSummary() string {
	var out bytes.Buffer
	out.WriteString("READ ADMIN: 21 read scopes\n\n")
	for _, group := range lanclient.WindowsReadAdminGroupsV14() {
		fmt.Fprintf(&out, "%s: %s\n\n", group.Name, group.Summary)
	}
	out.WriteString("Uses the same limited LocalService identity. Provider presence and service-token access are unverified; missing or denied sources remain unknown. No provider installation or privilege change.\n\nSelected event-message text is included only for exact accepted historical search rows, after a deliberate operator request. The profile excludes cached WUA inspection, service control and external-AI access. Selected-account HKCU/MSIX software is separate and off. Its foreground helper must be run and approved by the intended normal user; Setup never reads its own account as that user. Full scope disclosures and provider requirements are available under Scope details.")
	return out.String()
}

func setupWizardReadAdminDisclosure(insecure bool) string {
	var out bytes.Buffer
	out.WriteString("READ ADMIN: 21 explicit read scopes, using the same limited LocalService identity.\n\n")
	for _, group := range lanclient.WindowsReadAdminGroupsV14() {
		fmt.Fprintf(&out, "%s: %s\nRequirements: %s\n\n", group.Name, group.Summary, group.Prerequisites)
	}
	out.WriteString("Provider presence has not been checked. Actual LocalService readability is not verified by installer-admin access. Missing or denied sources remain unknown; Setup does not install providers, grant privileges, change ACLs or repair Windows settings.\n\nSelected event-message text from accepted historical search rows is explicitly included in this new fresh history approval. The older independent sampled-event content scope, cached WUA update inspection and service control remain separate optional approvals. Selected-account HKCU/MSIX software remains separately default off. Enabling the receive scope does not read an account: run the one-shot foreground helper in the selected normal user session and approve each bounded capture. Never use the elevated Setup account as a substitute. No external-AI access is included.\n\nFULL SCOPE DISCLOSURES\n")
	_ = writeReadSetupDisclosure(&out, freshReadAdminSetupConsent(insecure))
	out.WriteString("\nSource-only preview: exact Windows/native acceptance and released artifacts remain separately gated. Existing installations cannot use this fresh installer. Startup remains disabled until identity activation and every selected grant is verified. Interrupted writes retain partial evidence and cannot be retried or reset automatically.")
	return out.String()
}

func setupWizardReadAdminAcknowledgedBootstrap(raw []byte, insecure bool, renewal ...bool) (enrollmentclient.Bootstrap, lanclient.WindowsCapabilityConsent, error) {
	b, _, e := setupWizardAcknowledgedBootstrap(raw, insecure, renewal...)
	if e != nil {
		return b, lanclient.WindowsCapabilityConsent{}, e
	}
	return b, freshReadAdminSetupConsent(insecure), nil
}

// Bind every fresh grant to the sender recorded before grants-started. A new
// library call must not establish a replacement identity as its own baseline.
func readAdminFreshGrantReceipt(raw []byte, consent lanclient.WindowsCapabilityConsent, currentBinding string) (windowsservice.Receipt, error) {
	var r installReceipt
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal(raw, &r) != nil {
		return windowsservice.Receipt{}, errLifecycle
	}
	canonical, e := json.Marshal(r)
	if e != nil || !bytes.Equal(raw, canonical) || r.Version != readSetupReceiptVersion(consent) || !r.Prepared || r.Service.Version != 2 || !r.Service.Complete || r.ReadSetup == nil || r.ReadSetup.Phase != "grants-started" || validateReadSetupConsent(consent) != nil || (consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV5 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV6 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV7 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV8 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV9 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV10 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV11 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV12 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV13 && consent.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV14) || !reflect.DeepEqual(r.ReadSetup.Consent, consent) || !validReadSetupBinding(r.ReadSetup.SenderBinding) || currentBinding != r.ReadSetup.SenderBinding {
		return windowsservice.Receipt{}, errLifecycle
	}
	return r.Service, nil
}
