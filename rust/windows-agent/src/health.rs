//! Bounded derived diagnostics, never enrollment or sender authority. The sidecar
//! cannot initialize, repair, reset or replace either authoritative ledger.
use crate::{
    config::{Config, read_bounded, read_ca},
    protocol::AcceptedReceipt,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

pub const SCHEMA: &str = "tracebolt.rust-agent-health.v1";
pub const MAX_BYTES: u64 = 8192;
const FILE: &str = "health-v1.json";
const TEMP: &str = "health-v1.tmp";
pub const MAX_RETRY_SECONDS: u64 = 3600;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    NotObserved,
    AttemptInProgress,
    RegistrationPending,
    PendingApproval,
    Accepted,
    ReceiptStale,
    CertificateExpiring,
    ConfigurationInvalid,
    StateUnavailable,
    StateCorrupt,
    ClockInvalid,
    CollectionFailed,
    TransportTimeout,
    TransportTlsFailed,
    TransportConnectionRefused,
    TransportUnreachable,
    TransportUnclassified,
    AuthenticationRejected,
    ManagerRejected,
    ProtocolUnavailable,
    ReceiptInvalid,
    CertificateExpired,
    CertificateNotYetValid,
    EnrollmentExpired,
    EnrollmentRevoked,
    EnrollmentTerminated,
    UnclassifiedFailure,
    HealthUnavailable,
}
impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotObserved => "not-observed",
            Self::AttemptInProgress => "attempt-in-progress",
            Self::RegistrationPending => "registration-pending",
            Self::PendingApproval => "pending-approval",
            Self::Accepted => "accepted",
            Self::ReceiptStale => "receipt-stale",
            Self::CertificateExpiring => "certificate-expiring",
            Self::ConfigurationInvalid => "configuration-invalid",
            Self::StateUnavailable => "state-unavailable",
            Self::StateCorrupt => "state-corrupt",
            Self::ClockInvalid => "clock-invalid",
            Self::CollectionFailed => "collection-failed",
            Self::TransportTimeout => "transport-timeout",
            Self::TransportTlsFailed => "transport-tls-failed",
            Self::TransportConnectionRefused => "transport-connection-refused",
            Self::TransportUnreachable => "transport-unreachable",
            Self::TransportUnclassified => "transport-unclassified",
            Self::AuthenticationRejected => "authentication-rejected",
            Self::ManagerRejected => "manager-rejected",
            Self::ProtocolUnavailable => "protocol-unavailable",
            Self::ReceiptInvalid => "receipt-invalid",
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotYetValid => "certificate-not-yet-valid",
            Self::EnrollmentExpired => "enrollment-expired",
            Self::EnrollmentRevoked => "enrollment-revoked",
            Self::EnrollmentTerminated => "enrollment-terminated",
            Self::UnclassifiedFailure => "unclassified-failure",
            Self::HealthUnavailable => "health-unavailable",
        }
    }
    pub fn next_action(self) -> &'static str {
        match self {
            Self::ReceiptStale => {
                "The last validated receipt is stale. Inspect the approved service and connectivity locally; do not equate Running with a fresh accepted report."
            }
            Self::CertificateExpiring => {
                "The recorded credential expires within 24 hours. Review it with the custodian; no renewal, re-enrollment or identity replacement is authorized by diagnostics."
            }
            Self::NotObserved => {
                "No recorded attempt. Check the separately approved service and original setup; do not infer receipt from Running."
            }
            Self::AttemptInProgress => {
                "The latest attempt has no recorded completion. Inspect service state locally; do not retry or reset identity to repair uncertainty."
            }
            Self::RegistrationPending => {
                "Review the existing registration and manager reachability; preserve the same identity and state."
            }
            Self::PendingApproval => {
                "Compare the existing device fingerprint and comparison value with the manager before deliberate approval."
            }
            Self::Accepted => {
                "Check original receipt and collection times in the manager. This is not a live service or reachability probe."
            }
            Self::ConfigurationInvalid => {
                "Review protected configuration locally without printing values, weakening TLS or replacing identity."
            }
            Self::StateUnavailable | Self::StateCorrupt => {
                "Stop dependent recovery actions. Preserve ledgers, pending bytes and sequence floors; use a separately reviewed recovery procedure, never reset state."
            }
            Self::ClockInvalid => {
                "Review UTC time locally. Do not refresh original sample, receipt or certificate timestamps."
            }
            Self::CollectionFailed => {
                "Inspect the approved basic source locally; collection failure is not a zero or healthy measurement."
            }
            Self::TransportTlsFailed => {
                "The selected TLS connection failed. Review approved trust, peer identity, certificate validity and TLS policy locally; never disable verification or infer enrollment revocation."
            }
            Self::TransportConnectionRefused => {
                "The connection was refused at this attempt. Review the approved listener, port and network policy locally; refusal does not establish that the endpoint is offline."
            }
            Self::TransportUnreachable => {
                "The network reported an unreachable destination at this attempt. Review approved routing and connectivity locally; this is not proof that the endpoint or manager is offline."
            }
            Self::TransportTimeout | Self::TransportUnclassified => {
                "Review approved DNS, routing, TLS trust and manager availability locally. This class does not guess DNS versus TLS or prove offline status."
            }
            Self::AuthenticationRejected => {
                "Review exact identity, certificate and manager authorization. HTTP rejection alone does not prove revocation."
            }
            Self::ManagerRejected => {
                "Review the existing manager status and approved configuration; do not automatically replace credentials or replay a new identity."
            }
            Self::ProtocolUnavailable => {
                "Select matching reviewed manager/agent protocol and endpoint artifacts; do not downgrade TLS or infer compatibility."
            }
            Self::ReceiptInvalid => {
                "No acceptance was recorded. Review exact manager protocol and receipt identity/time; pending bytes and sequence state remain authoritative."
            }
            Self::CertificateExpired | Self::CertificateNotYetValid => {
                "Review UTC time and credential validity with the custodian; no renewal, re-enrollment or identity replacement is authorized by diagnostics."
            }
            Self::EnrollmentExpired | Self::EnrollmentRevoked | Self::EnrollmentTerminated => {
                "The manager reported a terminal enrollment state. Preserve identity and ledgers; no automatic rearm or replacement is permitted."
            }
            Self::UnclassifiedFailure => {
                "Inspect the failure locally through approved diagnostics. Raw errors and remote bodies are intentionally not exported."
            }
            Self::HealthUnavailable => {
                "Derived diagnostics are missing, invalid or unavailable. Preserve all files and inspect locally; do not delete ledgers or infer successful collection."
            }
        }
    }
}
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for Code {}

/// Classify types only: never scrape exception messages, URLs or remote bodies.
pub fn classify(error: &anyhow::Error) -> Code {
    if error.downcast_ref::<rusqlite::Error>().is_some_and(|e| matches!(e,
        rusqlite::Error::SqliteFailure(f, _) if matches!(f.code, rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase))) {
        return Code::StateCorrupt;
    }
    if let Some(code) = error.downcast_ref::<Code>() {
        return *code;
    }
    if let Some(e) = error.downcast_ref::<reqwest::Error>() {
        return if e.is_timeout() {
            Code::TransportTimeout
        } else {
            transport_cause(e).unwrap_or(Code::TransportUnclassified)
        };
    }
    if error.downcast_ref::<rusqlite::Error>().is_some() {
        return Code::StateUnavailable;
    }
    Code::UnclassifiedFailure
}

/// Inspect only typed causes within a reqwest failure. io::Error may hold the
/// TLS cause in get_ref() rather than expose that object through source(). Bound
/// traversal even if a future dependency supplies a cyclic custom error chain.
/// Other/NotFound and raw OS values are not portable DNS evidence. In particular,
/// connection refusal or unreachability never establishes an offline endpoint.
fn transport_cause(mut cause: &(dyn std::error::Error + 'static)) -> Option<Code> {
    for _ in 0..32 {
        if cause.downcast_ref::<rustls::Error>().is_some() {
            return Some(Code::TransportTlsFailed);
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            match error.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    return Some(Code::TransportConnectionRefused);
                }
                std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable => {
                    return Some(Code::TransportUnreachable);
                }
                _ => {}
            }
            if let Some(inner) = error.get_ref() {
                cause = inner;
                continue;
            }
        }
        cause = cause.source()?;
    }
    None
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    schema_version: String,
    configuration_binding: String,
    last_attempt_at: Option<DateTime<Utc>>,
    last_attempt_result: Code,
    last_accepted_receipt: Option<AcceptedReceipt>,
    receipt_observed_at: Option<DateTime<Utc>>,
    certificate_not_after: Option<DateTime<Utc>>,
    consecutive_failures: u32,
    retry_delay_seconds: u64,
    next_attempt_at: Option<DateTime<Utc>>,
}
impl Snapshot {
    fn new(binding: String) -> Self {
        Self {
            schema_version: SCHEMA.into(),
            configuration_binding: binding,
            last_attempt_at: None,
            last_attempt_result: Code::NotObserved,
            last_accepted_receipt: None,
            receipt_observed_at: None,
            certificate_not_after: None,
            consecutive_failures: 0,
            retry_delay_seconds: 0,
            next_attempt_at: None,
        }
    }
    fn validate(&self, binding: &str) -> Result<()> {
        for at in [
            self.last_attempt_at,
            self.receipt_observed_at,
            self.certificate_not_after,
            self.next_attempt_at,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(valid_time(at), "invalid diagnostic UTC time");
        }
        ensure!(
            self.schema_version == SCHEMA
                && self.configuration_binding == binding
                && binding.len() == 64
                && binding
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                && self.consecutive_failures <= 16
                && self.retry_delay_seconds <= MAX_RETRY_SECONDS,
            "invalid derived health state"
        );
        ensure!(
            self.last_accepted_receipt.is_some() == self.receipt_observed_at.is_some(),
            "incomplete receipt metadata"
        );
        ensure!(
            self.last_attempt_result != Code::Accepted
                || (self.last_accepted_receipt.is_some() && self.last_attempt_at.is_some()),
            "acceptance without recorded receipt"
        );
        if let Some(receipt) = &self.last_accepted_receipt {
            let earliest = receipt
                .collected_at
                .checked_sub_signed(chrono::Duration::seconds(30))
                .ok_or(Code::HealthUnavailable)?;
            ensure!(
                valid_time(receipt.collected_at)
                    && valid_time(receipt.received_at)
                    && (1..=crate::protocol::MAX_SEQUENCE).contains(&receipt.sequence)
                    && receipt.received_at >= earliest,
                "invalid receipt metadata"
            );
        }
        ensure!(
            self.last_attempt_at.is_some()
                || (self.last_attempt_result == Code::NotObserved
                    && self.next_attempt_at.is_none()),
            "invalid attempt metadata"
        );
        Ok(())
    }
}

/// The output type has no field for paths, hostnames, IDs, raw errors, telemetry,
/// private keys, certificates, passwords, cookies, tokens or remote response prose.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub schema_version: &'static str,
    pub observed_at: DateTime<Utc>,
    pub state: Code,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_attempt_result: Code,
    pub last_accepted_receipt: Option<AcceptedReceipt>,
    pub receipt_observed_at: Option<DateTime<Utc>>,
    pub receipt_freshness: &'static str,
    pub certificate_not_after: Option<DateTime<Utc>>,
    pub certificate_status: &'static str,
    pub consecutive_failures: u32,
    pub retry_delay_seconds: u64,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub next_action: &'static str,
    pub service_state: &'static str,
    pub evidence: &'static str,
    pub limitations: [&'static str; 3],
}
fn valid_time(at: DateTime<Utc>) -> bool {
    (1..=253_402_300_799).contains(&at.timestamp())
}

fn view(snapshot: Snapshot, now: DateTime<Utc>, interval: u64) -> Status {
    let mut state = snapshot.last_attempt_result;
    let within_day = now
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let clock_allowance = now
        .checked_add_signed(chrono::Duration::seconds(30))
        .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let certificate_status = match snapshot.certificate_not_after {
        Some(at) if at <= now => {
            state = Code::CertificateExpired;
            "expired"
        }
        Some(at) if at <= within_day => "expiring",
        Some(_) => "within-recorded-validity",
        None => "unknown",
    };
    let receipt_freshness = match snapshot.receipt_observed_at {
        Some(at) if at > clock_allowance => {
            state = Code::ClockInvalid;
            "clock-unknown"
        }
        Some(at)
            if now.signed_duration_since(at).num_seconds()
                <= (interval.saturating_mul(3).clamp(120, 7200)) as i64 =>
        {
            "recent-validated-receipt"
        }
        Some(_) => "stale-validated-receipt",
        None => "no-accepted-receipt-recorded",
    };
    if !valid_time(now) {
        state = Code::ClockInvalid;
    }
    if state == Code::Accepted {
        if receipt_freshness == "stale-validated-receipt" {
            state = Code::ReceiptStale;
        } else if certificate_status == "expiring" {
            state = Code::CertificateExpiring;
        }
    }
    Status {
        schema_version: SCHEMA,
        observed_at: now,
        state,
        last_attempt_at: snapshot.last_attempt_at,
        last_attempt_result: snapshot.last_attempt_result,
        last_accepted_receipt: snapshot.last_accepted_receipt,
        receipt_observed_at: snapshot.receipt_observed_at,
        receipt_freshness,
        certificate_not_after: snapshot.certificate_not_after,
        certificate_status,
        consecutive_failures: snapshot.consecutive_failures,
        retry_delay_seconds: snapshot.retry_delay_seconds,
        next_attempt_at: snapshot.next_attempt_at,
        next_action: state.next_action(),
        service_state: "not-inspected",
        evidence: "Acceptance metadata is recorded only after an identity/sequence/time-bound TLS manager receipt and durable local sequence advance. Receipt receivedAt is manager UTC; receiptObservedAt and attempt times are local UTC.",
        limitations: [
            "Derived diagnostics are not identity, revocation or replay authority; backup rollback and same-account tampering are not detected.",
            "No live network, SCM, provider or authoritative ledger inspection is performed by status/support-bundle. Startup failures before the first recorded attempt can remain unknown.",
            "DNS versus TLS failures are not guessed from raw error strings; unclassified transport failures remain explicit. Native Windows event integration and full Windows/Linux/browser acceptance are separate gates.",
        ],
    }
}

fn state_directory(directory: &Path) -> Result<PathBuf> {
    ensure!(directory.is_absolute(), "absolute directory required");
    for path in directory.ancestors() {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "unprotected diagnostic directory"
        );
    }
    let state = directory.join("state");
    let meta = fs::symlink_metadata(&state)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "unprotected diagnostic directory"
    );
    Ok(state)
}
fn load(path: &Path, binding: &str) -> Result<Snapshot> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "invalid diagnostic file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.nlink() == 1 && meta.mode() & 0o077 == 0,
            "shared diagnostic file"
        );
    }
    let snapshot: Snapshot = serde_json::from_slice(&read_bounded(path, MAX_BYTES)?)?;
    snapshot.validate(binding)?;
    Ok(snapshot)
}

pub struct Tracker {
    state: PathBuf,
    snapshot: Snapshot,
}
impl Tracker {
    /// Missing derived metadata means unobserved, never fresh/healthy. Invalid
    /// metadata disables diagnostics rather than repairing or resetting a ledger.
    pub fn open(directory: &Path, config: &Config) -> Result<Self> {
        let state = state_directory(directory)?;
        let binding = config.binding(&[], &read_ca(directory)?)?;
        let path = state.join(FILE);
        let snapshot = match fs::symlink_metadata(&path) {
            Ok(_) => load(&path, &binding)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Snapshot::new(binding),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { state, snapshot })
    }
    pub fn last_code(&self) -> Code {
        self.snapshot.last_attempt_result
    }
    pub fn attempt(&mut self, at: DateTime<Utc>) -> Result<()> {
        self.snapshot.last_attempt_at = Some(at);
        self.snapshot.last_attempt_result = Code::AttemptInProgress;
        self.snapshot.next_attempt_at = None;
        self.persist()
    }
    pub fn complete(
        &mut self,
        code: Code,
        receipt: Option<AcceptedReceipt>,
        at: DateTime<Utc>,
        failures: u32,
        delay: Duration,
        certificate_not_after: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.snapshot.last_attempt_result = code;
        if let Some(receipt) = receipt {
            self.snapshot.last_accepted_receipt = Some(receipt);
            self.snapshot.receipt_observed_at = Some(at);
        }
        self.snapshot.certificate_not_after = certificate_not_after;
        self.snapshot.consecutive_failures = failures.min(16);
        self.snapshot.retry_delay_seconds = delay.as_secs().min(MAX_RETRY_SECONDS);
        self.snapshot.next_attempt_at = Some(
            at.checked_add_signed(chrono::Duration::seconds(
                self.snapshot.retry_delay_seconds as i64,
            ))
            .ok_or(Code::ClockInvalid)?,
        );
        self.persist()
    }
    fn persist(&self) -> Result<()> {
        self.snapshot
            .validate(&self.snapshot.configuration_binding)?;
        // Never replace an unknown schema, mismatched source or symlink target.
        let target = self.state.join(FILE);
        match fs::symlink_metadata(&target) {
            Ok(_) => {
                load(&target, &self.snapshot.configuration_binding)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let raw = serde_json::to_vec(&self.snapshot)?;
        ensure!(
            raw.len() as u64 <= MAX_BYTES,
            "health snapshot exceeds limit"
        );
        let temporary = self.state.join(TEMP);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        #[cfg(unix)]
        fs::File::open(&self.state)?.sync_all()?;
        // On any failure retain uncertain temporary/target bytes for inspection.
        Ok(())
    }
}

/// Read-only: no runtime/sender/enrollment open, locks, DB, sidecar creation,
/// recovery, network or host operation. Corrupt diagnostics export static unknown.
pub fn status(directory: &Path, now: DateTime<Utc>) -> Status {
    let loaded = (|| -> Result<(Snapshot, u64)> {
        let config = Config::load(directory).context(Code::ConfigurationInvalid)?;
        let tracker = Tracker::open(directory, &config)?;
        Ok((tracker.snapshot, config.interval_seconds))
    })();
    match loaded {
        Ok((snapshot, interval)) => view(snapshot, now, interval),
        Err(error) => {
            let mut snapshot = Snapshot::new("0".repeat(64));
            snapshot.last_attempt_result =
                if error.downcast_ref::<Code>() == Some(&Code::ConfigurationInvalid) {
                    Code::ConfigurationInvalid
                } else {
                    Code::HealthUnavailable
                };
            view(snapshot, now, 60)
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    schema_version: &'static str,
    product: &'static str,
    version: &'static str,
    execution_platform: &'static str,
    architecture: &'static str,
    diagnostic: Status,
}
pub fn support_bundle(directory: &Path, now: DateTime<Utc>) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(&Bundle {
        schema_version: "tracebolt.rust-agent-support.v1",
        product: "Tracebolt",
        version: env!("CARGO_PKG_VERSION"),
        execution_platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        diagnostic: status(directory, now),
    })?;
    ensure!(
        raw.len() as u64 <= MAX_BYTES,
        "support metadata exceeds limit"
    );
    Ok(raw)
}

/// Retry scheduling changes timing only, never pending bytes, sequence floors,
/// identity or claim semantics. Injected jitter is bounded and not security entropy.
pub fn retry_delay(base: Duration, failures: u32, jitter: u8) -> Duration {
    let base = base.as_secs().clamp(30, MAX_RETRY_SECONDS);
    let seconds = base
        .saturating_mul(1u64 << failures.saturating_sub(1).min(7))
        .min(MAX_RETRY_SECONDS);
    Duration::from_secs(
        seconds
            .saturating_add(u64::from(jitter).min(30))
            .min(MAX_RETRY_SECONDS),
    )
}
