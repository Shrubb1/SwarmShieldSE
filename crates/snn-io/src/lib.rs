//! `snn-io` — persistent memory for the SNN.
//!
//! A [`Checkpoint`] captures *everything* needed for bit-identical resume:
//! synaptic weights, neuron membrane potentials and refractory counters,
//! STDP traces, in-flight delayed spikes, and the global step counter.
//! Serialization is `serde` + `bincode` — a compact `Vec<u8>` that can go
//! to a file today or a Postgres `bytea` row in Phase 2 unchanged.
//!
//! ```ignore
//! let bytes = snn_io::to_bytes(&Checkpoint::capture(&net, &learners))?;
//! // ... store bytes ...
//! let ck = snn_io::from_bytes(&bytes)?;
//! let (mut net, mut learners) = ck.restore()?;
//! ```

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use snn_core::Network;
use snn_learn::StdpLearner;

/// Current on-disk format version. Bump on breaking layout changes so old
/// checkpoints fail loudly instead of deserializing into garbage.
///
/// v2: added `aux` — named opaque blobs so higher layers (encoders,
/// detector bookkeeping) can ride along in the same checkpoint.
/// v3: `DetectorState` (in snn-mesh's aux) gained `up_free_streak`.
/// v4: firewall detectors widened 6→9 channels (meta: port entropy,
/// error rate, TCP share appended by `Firewall::evaluate`).
/// v5: 9→13 channels (post_share, mean_path, ua_diversity, payload_ent)
/// + DeltaModulator per-metric thresholds in the encoder aux.
pub const FORMAT_VERSION: u32 = 6;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub step_count: u64,
    pub network: Network,
    pub learners: Vec<StdpLearner>,
    /// Named component state owned by layers above snn-io (e.g. the
    /// telemetry encoder's delta baselines). Bincode-serialized blobs.
    pub aux: std::collections::BTreeMap<String, Vec<u8>>,
}

impl Checkpoint {
    /// Snapshot a running system.
    pub fn capture(network: &Network, learners: &[StdpLearner]) -> Self {
        Self {
            version: FORMAT_VERSION,
            step_count: network.step_count,
            network: network.clone(),
            learners: learners.to_vec(),
            aux: std::collections::BTreeMap::new(),
        }
    }

    /// Serialize `state` into the `aux` slot `name` (idempotent).
    pub fn set_aux<T: Serialize>(&mut self, name: &str, state: &T) -> io::Result<()> {
        self.aux
            .insert(name.to_string(), bincode::serialize(state).map_err(to_io)?);
        Ok(())
    }

    /// Deserialize the `aux` slot `name`. `Ok(None)` if absent.
    pub fn get_aux<T: serde::de::DeserializeOwned>(&self, name: &str) -> io::Result<Option<T>> {
        self.aux
            .get(name)
            .map(|b| bincode::deserialize(b).map_err(to_io))
            .transpose()
    }

    /// Rebuild the system. Errors on a format version mismatch.
    pub fn restore(self) -> io::Result<(Network, Vec<StdpLearner>)> {
        if self.version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "checkpoint version {} != supported {}",
                    self.version, FORMAT_VERSION
                ),
            ));
        }
        Ok((self.network, self.learners))
    }
}

fn to_io(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Serialize to bytes — what a Postgres `bytea` column will hold.
pub fn to_bytes(ck: &Checkpoint) -> io::Result<Vec<u8>> {
    bincode::serialize(ck).map_err(to_io)
}

/// Deserialize from bytes produced by [`to_bytes`].
pub fn from_bytes(bytes: &[u8]) -> io::Result<Checkpoint> {
    bincode::deserialize(bytes).map_err(to_io)
}

/// Write a checkpoint file (local cache / crash recovery path).
pub fn save<P: AsRef<Path>>(ck: &Checkpoint, path: P) -> io::Result<()> {
    std::fs::write(path, to_bytes(ck)?)
}

/// Load a checkpoint file written by [`save`].
pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Checkpoint> {
    from_bytes(&std::fs::read(path)?)
}
