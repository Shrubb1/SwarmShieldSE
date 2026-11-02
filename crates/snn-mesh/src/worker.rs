//! Reference worker loop: telemetry samples in on one `mpsc` channel,
//! `Detection` events out on another. This is the seam the orchestrator
//! plugs into — swap the channels for your IPC/Wasm boundary and the
//! detector side is unchanged.
//!
//! The loop is single-threaded by design: each detector is owned by
//! exactly one worker. Fan-out across workers/shards is a mesh-level
//! concern; inside a worker everything is `&mut` and deterministic.

use std::io;
use std::sync::mpsc::{Receiver, Sender};

use crate::agent::Agent;
use crate::detector::{Detection, TelemetrySample};
use crate::store::CheckpointStore;

/// Consume `rx` until the sender drops (producer signalled shutdown),
/// forwarding each [`Detection`] on `tx`. Returns samples processed.
///
/// Checkpoints on the agent's cadence and once at the end, so a clean
/// producer shutdown never loses un-persisted learning.
pub fn run_worker<S: CheckpointStore>(
    agent: &mut Agent<S>,
    rx: &Receiver<TelemetrySample>,
    tx: &Sender<Detection>,
) -> io::Result<u64> {
    let mut n = 0u64;
    while let Ok(sample) = rx.recv() {
        let detection = agent.observe(&sample)?;
        // If the detection consumer is gone, that's our exit too — but
        // flush first so the learning isn't lost.
        if tx.send(detection).is_err() {
            break;
        }
        n += 1;
    }
    agent.flush()?;
    Ok(n)
}
