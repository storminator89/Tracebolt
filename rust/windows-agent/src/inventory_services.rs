//! Inert caller-visible service-status collector port. Compiled only in unit
//! tests; never linked into the installed agent or called by Basic collection.
//! Local consent AND a fresh authenticated inventory authority are prerequisites
//! for any future integration. This module creates neither of them.

use serde::Serialize;
use std::mem::size_of;

const MAX_BUFFER_BYTES: usize = 256 << 10;
const MAX_OBSERVED: usize = 2048;
const MAX_ROWS: usize = 128;
const MAX_SECTION_BYTES: usize = 32 << 10;
const SOURCE: &str = "advapi32.OpenSCManagerW/EnumServicesStatusExW; SC_MANAGER_ENUMERATE_SERVICE";
const SCOPE: &str = "Caller-visible Win32 service names/status/PID only; services without QUERY_STATUS rights may be silently omitted; no drivers, configuration or service control; PID is zero when unavailable";

// Native ABI layout, with all scalar status fields retained only to calculate
// offsets. No native pointer is dereferenced by the decoder.
#[repr(C)]
struct EntryLayout {
    name: usize,
    display_name: usize,
    status: [u32; 9],
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Service {
    name: String,
    display_name: String,
    state: &'static str,
    pid: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Section {
    source: &'static str,
    scope: &'static str,
    quality: &'static str,
    observed_count: usize,
    count_exact: bool,
    complete: bool,
    truncated: bool,
    rows: Vec<Service>,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Denied,
    Unavailable,
}

struct Enumeration {
    // Word alignment is required by the native API. All storage is initialized
    // before passing it to Windows; only this bounded arena may contain strings.
    storage: Vec<usize>,
    count: u32,
    more_data: bool,
}

impl Enumeration {
    fn new() -> Self {
        Self {
            storage: vec![0; MAX_BUFFER_BYTES / size_of::<usize>()],
            count: 0,
            more_data: false,
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: usize has no padding/uninitialized bytes, storage stays alive
        // and immutable for the returned slice, and its length is fixed/bounded.
        unsafe {
            std::slice::from_raw_parts(
                self.storage.as_ptr().cast(),
                self.storage.len() * size_of::<usize>(),
            )
        }
    }
}

trait Provider {
    fn enumerate(&mut self) -> Result<Enumeration, Failure>;
}

fn empty(quality: &'static str) -> Section {
    Section {
        source: SOURCE,
        scope: SCOPE,
        quality,
        observed_count: 0,
        count_exact: false,
        complete: false,
        truncated: false,
        rows: Vec::new(),
    }
}

fn collect(provider: &mut impl Provider) -> Section {
    let page = match provider.enumerate() {
        Ok(page) => page,
        Err(Failure::Denied) => return empty("denied"),
        Err(Failure::Unavailable) => return empty("unavailable"),
    };
    decode(&page)
}

fn decode(page: &Enumeration) -> Section {
    let bytes = page.bytes();
    let count = page.count as usize;
    let Some(table_bytes) = count.checked_mul(size_of::<EntryLayout>()) else {
        return empty("unavailable");
    };
    if bytes.len() != MAX_BUFFER_BYTES || count > MAX_OBSERVED || table_bytes > bytes.len() {
        return empty("unavailable");
    }
    let mut section = empty("healthy");
    section.complete = !page.more_data;
    section.truncated = page.more_data;
    for row in bytes[..table_bytes]
        .as_chunks::<{ size_of::<EntryLayout>() }>()
        .0
    {
        let pointer =
            |at| usize::from_ne_bytes(row[at..at + size_of::<usize>()].try_into().unwrap());
        let number = |at| u32::from_ne_bytes(row[at..at + 4].try_into().unwrap());
        let fields = size_of::<usize>() * 2;
        let state = match number(fields + 4) {
            1 => "stopped",
            2 => "start_pending",
            3 => "stop_pending",
            4 => "running",
            5 => "continue_pending",
            6 => "pause_pending",
            7 => "paused",
            _ => {
                section.complete = false;
                continue;
            }
        };
        let name = buffer_string(bytes, pointer(0), table_bytes, true);
        let display = buffer_string(bytes, pointer(size_of::<usize>()), table_bytes, false);
        let (Some(name), Some(display_name)) = (name, display) else {
            section.complete = false;
            continue;
        };
        // SERVICE_STATUS_PROCESS only defines PID in these four states. Never
        // copy an indeterminate transition-state value into the v1 numeric row.
        let pid = if matches!(
            state,
            "running" | "continue_pending" | "pause_pending" | "paused"
        ) {
            number(fields + 28)
        } else {
            0
        };
        section.rows.push(Service {
            name,
            display_name,
            state,
            pid,
        });
    }
    section.rows.sort_by(|a, b| {
        (&a.name, &a.display_name, a.state, a.pid).cmp(&(&b.name, &b.display_name, b.state, b.pid))
    });
    section.observed_count = section.rows.len();
    section.count_exact = section.complete;
    if section.rows.len() > MAX_ROWS {
        section.rows.truncate(MAX_ROWS);
        section.complete = false;
        section.truncated = true;
    }
    if !section.complete || section.truncated {
        section.quality = "partial";
    }
    // This section budget is not an aggregate-frame guarantee. Future admission
    // must also fit all other sections under windowsmanaged.MaxSnapshotBytes.
    while go_encoded_len(&section) > MAX_SECTION_BYTES {
        section.rows.pop();
        section.complete = false;
        section.truncated = true;
        section.quality = "partial";
    }
    section
}

fn go_encoded_len(section: &Section) -> usize {
    let encoded = serde_json::to_vec(section).unwrap();
    // Go's unchanged ingress re-encodes using encoding/json's default HTML
    // escaping. Each literal <, > or & becomes six bytes (\u00XX), not one.
    // U+2028/U+2029 are rejected by valid_text before reaching serialization.
    encoded.len()
        + encoded
            .iter()
            .filter(|b| matches!(b, b'<' | b'>' | b'&'))
            .count()
            * 5
}

fn buffer_string(
    bytes: &[u8],
    address: usize,
    table_bytes: usize,
    required: bool,
) -> Option<String> {
    let offset = address.checked_sub(bytes.as_ptr() as usize)?;
    if offset < table_bytes || offset >= bytes.len() || offset % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(256);
    for unit in bytes[offset..].as_chunks::<2>().0.iter().take(257) {
        let unit = u16::from_ne_bytes(*unit);
        if unit == 0 {
            let text = String::from_utf16(&units).ok()?;
            return valid_text(&text, required).then_some(text);
        }
        units.push(unit);
    }
    None
}

fn valid_text(text: &str, required: bool) -> bool {
    // Match the Go managed wire's byte bound and reject its Unicode control,
    // format, replacement and line/paragraph-separator exclusions. The Unicode
    // format ranges are deliberately explicit; no native labels enter logs.
    (!required || !text.trim().is_empty())
        && text.len() <= 256
        && !text.chars().any(|c| {
            c.is_control()
                || matches!(c as u32,
            0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f | 0x0890..=0x0891 |
            0x08e2 | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2064 |
            0x2066..=0x206f | 0xfeff | 0xfff9..=0xfffb | 0xfffd | 0x110bd | 0x110cd |
            0x13430..=0x1343f | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 |
            0xe0020..=0xe007f)
        })
}

// Compiled in Windows unit-test builds only, never invoked by a test. The
// installed Basic executable cannot reference this source candidate.
#[cfg(windows)]
#[allow(dead_code)]
mod native {
    use super::*;
    use std::ptr::null;
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_MORE_DATA, GetLastError},
        System::Services::{
            CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
            SC_HANDLE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
        },
    };

    pub(super) struct Native;
    struct Manager(SC_HANDLE);
    impl Drop for Manager {
        fn drop(&mut self) {
            // SAFETY: owns the single non-null handle returned by OpenSCManagerW.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    fn failure(error: u32) -> Failure {
        if error == ERROR_ACCESS_DENIED {
            Failure::Denied
        } else {
            Failure::Unavailable
        }
    }
    impl Provider for Native {
        fn enumerate(&mut self) -> Result<Enumeration, Failure> {
            // SAFETY: fixed local read-only SCM access; no machine/database,
            // service handle, control, config, privilege change or shell command.
            let handle = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
            if handle.is_null() {
                return Err(failure(unsafe { GetLastError() }));
            }
            let manager = Manager(handle);
            let mut page = Enumeration::new();
            let (mut needed, mut resume) = (0, 0);
            // Exactly one bounded enumeration. ERROR_MORE_DATA preserves a
            // partial prefix; no retry/resume can invent a complete generation.
            let ok = unsafe {
                EnumServicesStatusExW(
                    manager.0,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    page.storage.as_mut_ptr().cast(),
                    MAX_BUFFER_BYTES as u32,
                    &mut needed,
                    &mut page.count,
                    &mut resume,
                    null(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_MORE_DATA {
                    return Err(failure(error));
                }
                page.more_data = true;
            }
            Ok(page)
        }
    }

    #[test]
    fn layout_matches_windows_sdk() {
        use std::mem::offset_of;
        use windows_sys::Win32::System::Services::{
            ENUM_SERVICE_STATUS_PROCESSW, SERVICE_STATUS_PROCESS,
        };
        assert_eq!(
            size_of::<EntryLayout>(),
            size_of::<ENUM_SERVICE_STATUS_PROCESSW>()
        );
        assert_eq!(
            std::mem::align_of::<EntryLayout>(),
            std::mem::align_of::<ENUM_SERVICE_STATUS_PROCESSW>()
        );
        assert_eq!(
            offset_of!(EntryLayout, name),
            offset_of!(ENUM_SERVICE_STATUS_PROCESSW, lpServiceName)
        );
        assert_eq!(
            offset_of!(EntryLayout, display_name),
            offset_of!(ENUM_SERVICE_STATUS_PROCESSW, lpDisplayName)
        );
        assert_eq!(
            offset_of!(EntryLayout, status),
            offset_of!(ENUM_SERVICE_STATUS_PROCESSW, ServiceStatusProcess)
        );
        assert_eq!(offset_of!(SERVICE_STATUS_PROCESS, dwCurrentState), 4);
        assert_eq!(offset_of!(SERVICE_STATUS_PROCESS, dwProcessId), 28);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Invented in-memory API-shaped data. No host API is called on any platform.
    fn page(rows: &[(&str, &str, u32, u32)], more_data: bool) -> Enumeration {
        let mut page = Enumeration::new();
        page.count = rows.len() as u32;
        page.more_data = more_data;
        let base = page.storage.as_ptr() as usize;
        let mut bytes = vec![0u8; MAX_BUFFER_BYTES];
        let mut offset = rows.len() * size_of::<EntryLayout>();
        for (i, (name, display, state, pid)) in rows.iter().enumerate() {
            let row = i * size_of::<EntryLayout>();
            for (field, text) in [(0, name), (size_of::<usize>(), display)] {
                bytes[row + field..row + field + size_of::<usize>()]
                    .copy_from_slice(&(base + offset).to_ne_bytes());
                for unit in text.encode_utf16().chain(Some(0)) {
                    bytes[offset..offset + 2].copy_from_slice(&unit.to_ne_bytes());
                    offset += 2;
                }
            }
            let status = row + size_of::<usize>() * 2;
            bytes[status + 4..status + 8].copy_from_slice(&state.to_ne_bytes());
            bytes[status + 28..status + 32].copy_from_slice(&pid.to_ne_bytes());
        }
        for (word, data) in page
            .storage
            .iter_mut()
            .zip(bytes.as_chunks::<{ size_of::<usize>() }>().0.iter())
        {
            *word = usize::from_ne_bytes(*data);
        }
        page
    }

    struct Fake(Option<Result<Enumeration, Failure>>);
    impl Provider for Fake {
        fn enumerate(&mut self) -> Result<Enumeration, Failure> {
            self.0.take().expect("one native read only")
        }
    }

    #[test]
    fn visible_rows_sort_and_transition_pids_are_not_asserted() {
        let mut fake = Fake(Some(Ok(page(
            &[("Zulu", "Display", 4, 40), ("Alpha", "", 2, 999)],
            false,
        ))));
        let section = collect(&mut fake);
        assert_eq!(section.quality, "healthy");
        assert!(section.complete && section.count_exact && !section.truncated);
        assert_eq!(section.observed_count, 2);
        assert_eq!(section.rows[0].name, "Alpha");
        assert_eq!(section.rows[0].pid, 0);
        assert_eq!(section.rows[1].pid, 40);
    }

    #[test]
    fn all_seven_states_only_copy_documented_pids() {
        let names: Vec<_> = (1..=7).map(|i| format!("state-{i}")).collect();
        let rows: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), "", (i + 1) as u32, 99))
            .collect();
        let section = decode(&page(&rows, false));
        assert_eq!(section.rows.len(), 7);
        for (i, row) in section.rows.iter().enumerate() {
            assert_eq!(row.pid, if i < 3 { 0 } else { 99 });
        }
    }

    #[test]
    fn denial_failure_and_healthy_empty_are_distinct() {
        for (error, quality) in [
            (Failure::Denied, "denied"),
            (Failure::Unavailable, "unavailable"),
        ] {
            let section = collect(&mut Fake(Some(Err(error))));
            assert_eq!(section.quality, quality);
            assert!(!section.complete && !section.count_exact && section.rows.is_empty());
        }
        let section = decode(&page(&[], false));
        assert!(section.complete && section.count_exact);
        assert_eq!(section.quality, "healthy");
        let partial = decode(&page(&[], true));
        assert!(!partial.complete && !partial.count_exact && partial.truncated);
        assert_eq!(partial.quality, "partial");
    }

    #[test]
    fn native_and_transport_cutoffs_do_not_promote_prefixes() {
        let names: Vec<String> = (0..129).map(|i| format!("svc-{i:04}")).collect();
        let rows: Vec<_> = names.iter().map(|name| (name.as_str(), "", 4, 1)).collect();
        for more_data in [false, true] {
            let section = decode(&page(&rows, more_data));
            assert_eq!(section.observed_count, 129);
            assert_eq!(section.rows.len(), 128);
            assert!(!section.complete && section.truncated);
            assert_eq!(section.count_exact, !more_data);
            assert_eq!(section.quality, "partial");
        }
        let mut invalid = Enumeration::new();
        invalid.count = MAX_OBSERVED as u32 + 1;
        assert_eq!(decode(&invalid).quality, "unavailable");
        invalid.count = u32::MAX;
        assert_eq!(decode(&invalid).quality, "unavailable");
    }

    #[test]
    fn malformed_pointers_counts_and_utf16_never_escape_the_arena() {
        for address in [0, 1, usize::MAX] {
            let mut data = page(&[("name", "Display", 4, 1)], false);
            data.storage[0] = address;
            let section = decode(&data);
            assert!(!section.complete && !section.count_exact && section.rows.is_empty());
        }
        let data = page(&[("name", "Display", 4, 1)], false);
        let base = data.storage.as_ptr() as usize;
        for address in [
            base,
            base + size_of::<EntryLayout>() + 1,
            base + MAX_BUFFER_BYTES,
            base + MAX_BUFFER_BYTES - 1,
        ] {
            assert!(buffer_string(data.bytes(), address, size_of::<EntryLayout>(), true).is_none());
        }
        let mut invalid = page(&[("name", "Display", 4, 1)], false);
        // Unpaired high surrogate in the first name, no lossy replacement.
        let at = size_of::<EntryLayout>() / size_of::<usize>();
        invalid.storage[at] = 0xd800;
        assert!(!decode(&invalid).complete);
        assert!(decode(&invalid).rows.is_empty());
        let invalid = page(&[("name", "Display", 99, 1), ("good", "", 4, 2)], false);
        let section = decode(&invalid);
        assert_eq!(section.rows.len(), 1);
        assert!(!section.complete && !section.count_exact);
    }

    #[test]
    fn bounded_strings_reject_controls_formats_replacements_and_byte_overflow() {
        for text in [
            "",
            " ",
            "a\n",
            "a\u{200b}",
            "a\u{202e}",
            "a\u{fffd}",
            "a\u{2028}",
        ] {
            assert!(!valid_text(text, true), "{text:?}");
        }
        assert!(valid_text("", false));
        assert!(valid_text(&"a".repeat(256), true));
        assert!(!valid_text(&"a".repeat(257), true));
        assert!(!valid_text(&"é".repeat(129), true));
        let invalid = page(&[(&"a".repeat(257), "", 4, 1)], false);
        assert!(decode(&invalid).rows.is_empty());
        let max = page(&[(&"a".repeat(256), "", 4, 1)], false);
        assert!(decode(&max).complete);
        let mut no_terminator = page(&[("name", "", 4, 1)], false);
        let start = size_of::<EntryLayout>() / size_of::<usize>();
        for word in &mut no_terminator.storage[start..] {
            *word = usize::from_ne_bytes([0x41; size_of::<usize>()]);
        }
        assert!(decode(&no_terminator).rows.is_empty());
    }

    #[test]
    fn byte_trim_retains_original_count_and_exactness() {
        let names: Vec<_> = (0..128)
            .map(|i| format!("svc-{i:04}-{}", "n".repeat(240)))
            .collect();
        let display = "d".repeat(256);
        let rows: Vec<_> = names
            .iter()
            .map(|n| (n.as_str(), display.as_str(), 4, 10))
            .collect();
        let section = decode(&page(&rows, false));
        assert_eq!(section.observed_count, 128);
        assert!(section.count_exact && section.truncated && !section.complete);
        assert!(section.rows.len() < 128);
        assert!(serde_json::to_vec(&section).unwrap().len() <= MAX_SECTION_BYTES);
    }

    #[test]
    fn byte_budget_accounts_for_manager_html_escaping() {
        let names: Vec<_> = (0..128)
            .map(|i| format!("svc-{i:04}-{}", "<&>".repeat(80)))
            .collect();
        let rows: Vec<_> = names.iter().map(|n| (n.as_str(), "<&>", 4, 10)).collect();
        let section = decode(&page(&rows, false));
        assert_eq!(section.observed_count, 128);
        assert!(section.count_exact && section.truncated && !section.complete);
        assert!(section.rows.len() < MAX_ROWS);
        assert!(go_encoded_len(&section) <= MAX_SECTION_BYTES);
    }

    #[test]
    fn invented_wire_section_is_accepted_by_go_contract_fixture() {
        let section = decode(&page(
            &[("InventedService", "Invented display", 4, 42)],
            false,
        ));
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/rustagent/service-status-section.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(section).unwrap(), expected);
    }
}
