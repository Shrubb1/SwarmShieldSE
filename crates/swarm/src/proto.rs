//! Wire protocol: 4-byte big-endian length + JSON `Frame`.
//! Deliberately boring — same serde types as `JsonApi`, so a Wasm worker
//! speaks the identical dialect.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use serde::{Deserialize, Serialize};
use snn_firewall::{ConnEvent, MitigationRule, Verdict};
use snn_mesh::{Detection, TelemetrySample};

const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// Every message on the wire, both directions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Frame {
    /// Worker → orchestrator: identity on connect.
    Hello {
        worker_id: String,
        job_id: String,
    },
    /// Client → worker: enforce this connection event.
    Event(ConnEvent),
    /// Client → worker: telemetry tick.
    Sample(TelemetrySample),
    /// Worker → client: verdict / detection replies.
    Verdict(Verdict),
    Detection(Box<Detection>),
    /// Worker → orchestrator: reports (control-plane audit).
    Report(Report),
    /// Orchestrator → worker or either way: housekeeping.
    Flush,
    Ping,
    Pong,
    Shutdown,
    Err(String),
}

/// Upstream reports — what the control plane logs per job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Report {
    RuleApplied {
        job_id: String,
        rule: MitigationRule,
    },
    RuleRevoked {
        job_id: String,
        rule_id: u64,
    },
    Detection {
        job_id: String,
        detection: Box<Detection>,
    },
    Heartbeat {
        job_id: String,
        samples: u64,
    },
}

pub fn write_frame(stream: &mut TcpStream, frame: &Frame) -> io::Result<()> {
    let body = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME as usize {
        return Err(io::Error::other("frame too large"));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

pub fn read_frame(stream: &mut TcpStream) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds max"));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body)?;
    Ok(Some(
        serde_json::from_slice(&body).map_err(io::Error::other)?,
    ))
}
