use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rusqlite::{Connection, OpenFlags, params};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

pub struct State {
    connection: Connection,
    _lock: File,
}

/// Do not publish a failed foreground open as the active service's health.
/// This marker carries no private path or OS error prose.
#[derive(Debug)]
pub(crate) struct LockUnavailable;
impl std::fmt::Display for LockUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authoritative state lock unavailable")
    }
}
impl std::error::Error for LockUnavailable {}

impl State {
    pub fn enrolled(directory: &Path, binding: &str) -> Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("sender.lock"))?;
        lock.try_lock_exclusive().context(LockUnavailable)?;
        let mut connection = Connection::open_with_flags(
            directory.join("enrollment.db"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;")?;
        let tx = connection.transaction()?;
        let (activated, initialized): (bool, bool) = tx.query_row(
            "SELECT activated,sender_initialized FROM enrollment WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(activated, "enrollment not activated");
        if !initialized {
            tx.execute_batch("CREATE TABLE sender(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,next INTEGER NOT NULL,pending BLOB);")?;
            tx.execute("INSERT INTO sender VALUES(1,?1,1,NULL)", [binding])?;
            tx.execute("UPDATE enrollment SET sender_initialized=1 WHERE id=1", [])?;
        }
        let stored: String =
            tx.query_row("SELECT binding FROM sender WHERE id=1", [], |r| r.get(0))?;
        ensure!(stored == binding, "sender identity mismatch");
        tx.commit()?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }
    pub fn open(directory: &Path, binding: &str, initialize: bool) -> Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("sender.lock"))?;
        lock.try_lock_exclusive().context(LockUnavailable)?;
        let path = directory.join("sender.db");
        if initialize {
            // Never adopt or reset existing state, even an incomplete initialization.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?
                .sync_all()?;
        }
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;")?;
        if initialize {
            let tx = connection.transaction()?;
            tx.execute_batch("CREATE TABLE sender(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, next INTEGER NOT NULL, pending BLOB);")?;
            tx.execute("INSERT INTO sender VALUES(1,?1,1,NULL)", [binding])?;
            tx.commit()?;
        }
        let stored: String =
            connection.query_row("SELECT binding FROM sender WHERE id=1", [], |row| {
                row.get(0)
            })?;
        ensure!(
            stored == binding,
            "state identity mismatch; do not reset state"
        );
        Ok(Self {
            connection,
            _lock: lock,
        })
    }
    pub fn current(&self) -> Result<(u64, Option<Vec<u8>>)> {
        let (sequence, pending) =
            self.connection
                .query_row("SELECT next,pending FROM sender WHERE id=1", [], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get(1)?))
                })?;
        ensure!(
            sequence > 0 && sequence <= crate::protocol::MAX_SEQUENCE as i64 + 1,
            "invalid sequence state"
        );
        Ok((sequence as u64, pending))
    }
    pub fn prepare(&self, sequence: u64, body: &[u8]) -> Result<()> {
        ensure!(
            sequence > 0 && sequence <= crate::protocol::MAX_SEQUENCE && body.len() <= 72 * 1024,
            "invalid pending frame"
        );
        ensure!(
            self.connection.execute(
                "UPDATE sender SET pending=?1 WHERE id=1 AND next=?2 AND pending IS NULL",
                params![body, sequence as i64]
            )? == 1,
            "pending state conflict"
        );
        Ok(())
    }
    // A stale sample consumes its sequence as well. It is never relabeled fresh.
    pub fn advance(&self, sequence: u64) -> Result<()> {
        ensure!(
            (1..=crate::protocol::MAX_SEQUENCE).contains(&sequence),
            "invalid sequence"
        );
        ensure!(self.connection.execute("UPDATE sender SET next=next+1,pending=NULL WHERE id=1 AND next=?1 AND pending IS NOT NULL", [sequence as i64])? == 1, "acknowledgement state conflict");
        Ok(())
    }
}
