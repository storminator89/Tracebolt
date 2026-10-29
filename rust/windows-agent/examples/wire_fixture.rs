// Invented offline sample, never reads the host or sends a report.
fn main() {
    use chrono::{TimeZone, Utc};
    use tracebolt_windows_agent::protocol::{Sample, frame};
    let bytes = frame(
        1,
        Utc.with_ymd_and_hms(2026, 10, 29, 12, 0, 0).unwrap(),
        Sample {
            cpu: Some(12.5),
            memory: Some(40.0),
            disk: Some(25.0),
            uptime: "123 seconds".into(),
        },
    )
    .unwrap();
    println!("{}", String::from_utf8(bytes).unwrap());
}
