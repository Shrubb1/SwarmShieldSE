//! [`Agent`] — the object a mesh worker actually holds.
//!
//! It owns the [`Detector`] plus its [`CheckpointStore`], and applies the
//! persistence policy: restore-on-boot, checkpoint every `checkpoint_every`
//! samples, and an explicit [`Agent::flush`] for shutdown.
//!
//! ```ignore
//! let mut agent = Agent::open(store, config, &initial_baselines)?;
//! let detection = agent.observe(&sample)?;      // auto-checkpoints
//! agent.flush()?;                                // final save on shutdown
//! ```

use std::io;

use snn_io::{from_bytes, to_bytes};

use crate::detector::{Detection, Detector, DetectorConfig, TelemetrySample};
use crate::store::CheckpointStore;

pub struct Agent<S: CheckpointStore> {
    pub detector: Detector,
    pub store: S,
    /// Checkpoint cadence, in observed samples. 0 = checkpoint every sample.
    pub checkpoint_every: u64,
}

impl<S: CheckpointStore> Agent<S> {
    /// Restore from `store` if a checkpoint exists, else build a fresh
    /// detector seeded with `initial_baselines`. Either way the agent is
    /// ready to `observe` immediately — workers don't branch on first-boot.
    pub fn open(store: S, config: DetectorConfig, initial_baselines: &[f32]) -> io::Result<Self> {
        let detector = match store.load()? {
            Some(bytes) => Detector::from_checkpoint(config, from_bytes(&bytes)?)?,
            None => Detector::new(config, initial_baselines),
        };
        Ok(Self {
            detector,
            store,
            checkpoint_every: 1000,
        })
    }

    /// Observe one sample; persist on the checkpoint cadence.
    pub fn observe(&mut self, sample: &TelemetrySample) -> io::Result<Detection> {
        let detection = self.detector.observe(sample);
        if self.checkpoint_every == 0
            || self
                .detector
                .samples_observed()
                .is_multiple_of(self.checkpoint_every)
        {
            self.flush()?;
        }
        Ok(detection)
    }

    /// Write a checkpoint now. Called automatically on cadence and should
    /// be called once more on shutdown.
    pub fn flush(&mut self) -> io::Result<()> {
        let ck = self.detector.checkpoint()?;
        let bytes = to_bytes(&ck)?;
        self.store.save(&bytes, ck.step_count)
    }
}
