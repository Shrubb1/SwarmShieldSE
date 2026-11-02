//! swarm-orchestrator — control-plane binary.
//!
//! swarm-orchestrator --listen 127.0.0.1:9000 --root ./mesh-data

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use swarm::run_orchestrator;

fn arg(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.into())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg(&args, "--listen", "127.0.0.1:9000");
    let root = PathBuf::from(arg(&args, "--root", "./mesh-data"));

    let listener = TcpListener::bind(&listen)?;
    eprintln!(
        "swarm-orchestrator listening on {listen}, jobs under {}",
        root.display()
    );

    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let _ = std::thread::spawn(move || {
        let _ = std::io::stdin().read_line(&mut String::new());
        s.store(true, Ordering::Relaxed);
    });
    let n = run_orchestrator(listener, root.join("jobs"), stop)?;
    eprintln!("{n} reports ingested");
    Ok(())
}
