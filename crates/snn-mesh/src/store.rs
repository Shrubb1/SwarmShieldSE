//! Where SNN memory lives between process lifetimes.
//!
//! [`CheckpointStore`] is deliberately minimal — raw bytes in/out — so the
//! same trait backs a temp file in tests, a Postgres `bytea` row in the
//! mesh, or IndexedDB/opfs inside a Wasm worker. The bytes are opaque
//! `snn_io` checkpoints; stores don't need to understand them.

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

/// Persistence backend for checkpoint bytes.
pub trait CheckpointStore: Send + Sync {
    /// The most recent checkpoint, or `None` on first boot.
    fn load(&self) -> io::Result<Option<Vec<u8>>>;
    /// Persist a checkpoint (overwrites the previous one).
    /// `step_count` is advisory for stores that index it (e.g. Postgres).
    fn save(&self, bytes: &[u8], step_count: u64) -> io::Result<()>;
}

// Borrowed and shared handles work as stores too — lets a caller keep
// ownership (tests, multi-agent shards) without `Arc` ceremony.
impl<T: CheckpointStore + ?Sized> CheckpointStore for &T {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        (**self).load()
    }
    fn save(&self, bytes: &[u8], step_count: u64) -> io::Result<()> {
        (**self).save(bytes, step_count)
    }
}

impl<T: CheckpointStore + ?Sized> CheckpointStore for std::sync::Arc<T> {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        (**self).load()
    }
    fn save(&self, bytes: &[u8], step_count: u64) -> io::Result<()> {
        (**self).save(bytes, step_count)
    }
}

/// Type-erased store — the orchestrator keeps heterogenous backends in
/// one collection.
impl CheckpointStore for Box<dyn CheckpointStore> {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        (**self).load()
    }
    fn save(&self, bytes: &[u8], step_count: u64) -> io::Result<()> {
        (**self).save(bytes, step_count)
    }
}

/// Single-file store — crash recovery path and tests.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CheckpointStore for FileStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn save(&self, bytes: &[u8], _step_count: u64) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write-then-rename: a crash mid-write leaves the old checkpoint
        // intact rather than a torn file.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// In-memory store — unit tests, Wasm workers that checkpoint elsewhere.
#[derive(Default)]
pub struct MemoryStore {
    slot: Mutex<Option<Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CheckpointStore for MemoryStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.lock().clone())
    }

    fn save(&self, bytes: &[u8], _step_count: u64) -> io::Result<()> {
        *self.lock() = Some(bytes.to_vec());
        Ok(())
    }
}

impl MemoryStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<u8>>> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Postgres-backed store. One row per detector instance in
/// `snn_checkpoints(name, state, step_count, updated_at)` — upserted, so
/// the table always holds the latest memory.
///
/// Uses the synchronous `postgres` client behind a `Mutex`: the store is
/// `Sync` and works from any worker context without dragging a tokio
/// runtime into crates that don't have one.
#[cfg(feature = "postgres-store")]
pub struct PostgresStore {
    client: Mutex<postgres::Client>,
    name: String,
}

#[cfg(feature = "postgres-store")]
impl PostgresStore {
    /// `conn` is a libpq connection string; `name` identifies this
    /// detector instance (e.g. `"{worker_id}:routing-snn"`).
    pub fn connect(conn: &str, name: impl Into<String>) -> Result<Self, postgres::Error> {
        let mut client = postgres::Client::connect(conn, postgres::NoTls)?;
        client.batch_execute(
            "CREATE TABLE IF NOT EXISTS snn_checkpoints (
                 name        TEXT PRIMARY KEY,
                 state       BYTEA NOT NULL,
                 step_count  BIGINT NOT NULL,
                 updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
             )",
        )?;
        Ok(Self {
            client: Mutex::new(client),
            name: name.into(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, postgres::Client> {
        self.client.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(feature = "postgres-store")]
impl CheckpointStore for PostgresStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let mut client = self.lock();
        let row = client
            .query_opt(
                "SELECT state FROM snn_checkpoints WHERE name = $1",
                &[&self.name],
            )
            .map_err(io::Error::other)?;
        Ok(row.map(|r| r.get(0)))
    }

    fn save(&self, bytes: &[u8], step_count: u64) -> io::Result<()> {
        let mut client = self.lock();
        client
            .execute(
                "INSERT INTO snn_checkpoints (name, state, step_count)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (name) DO UPDATE
                 SET state = $2, step_count = $3, updated_at = now()",
                &[&self.name, &bytes, &(step_count as i64)],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }
}
