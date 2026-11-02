//! `swarm_svc` — Windows Service Control Manager entrypoint. Runs the
//! same L4 guard headlessly; SCM sends STOP via the control handler.
//!
//! Install (admin): `sc create SwarmShieldSE binPath= "C:\...\swarm_svc.exe 9101:8081" start= auto`
//! Uninstall:        `sc delete SwarmShieldSE`

#![cfg(windows)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snn_firewall::{
    channel_names, ConnEvent, EventMeta, Firewall, FirewallPolicy, MemoryAudit, MitigationKind,
    RecordingPolicySink, Verdict,
};
use snn_mesh::DetectorConfig;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

static STOP: AtomicBool = AtomicBool::new(false);
define_windows_service!(ffi_service_main, service_main);

fn firewall() -> Firewall<RecordingPolicySink, MemoryAudit> {
    let mut p = FirewallPolicy {
        anomaly_threshold: 2,
        action_ladder: vec![
            MitigationKind::RateLimit { max_rps: 10.0 },
            MitigationKind::Drop,
            MitigationKind::Block,
        ],
        ttl_ms: 30_000,
        cooldown_ms: 0,
        ..Default::default()
    };
    p.search.enabled = true;
    Firewall::new(
        DetectorConfig {
            delta_threshold: 5.0,
            spike_current: 200.0,
            initial_weight: 80.0,
            window: 10,
            anomaly_threshold: 1,
            ..DetectorConfig::for_metrics(&channel_names())
        },
        p,
        &[10.0, 2.0, 5.0, 500.0, 400.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 10.0],
        RecordingPolicySink::default(),
        MemoryAudit::default(),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn tarpit(s: &mut TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 512];
    for _ in 0..40 {
        if STOP.load(Ordering::Relaxed) {
            return;
        }
        let _ = s.write_all(b"...");
        let _ = s.flush();
        let _ = s.read(&mut buf);
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn handle(
    mut client: TcpStream,
    target: &str,
    listen_port: u16,
    fw: &Arc<Mutex<Firewall<RecordingPolicySink, MemoryAudit>>>,
) {
    let src = client
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mut upstream = match TcpStream::connect(target) {
        Ok(u) => u,
        Err(_) => return,
    };
    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 8192];
    loop {
        if STOP.load(Ordering::Relaxed) {
            return;
        }
        match client.read(&mut buf) {
            Ok(0) => return,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
            Ok(n) => {
                let chunk = &buf[..n];
                let ev = ConnEvent {
                    ts_ms: now_ms(),
                    tenant: "t-a".into(),
                    src_ip: src,
                    payload_bytes: n as u32,
                    header_bytes: 0,
                    meta: EventMeta {
                        dst_port: listen_port,
                        proto: 6,
                        ..Default::default()
                    },
                    payload: Some(chunk.to_vec().into_boxed_slice()),
                };
                let v = fw.lock().unwrap().inspect(&ev).unwrap_or(Verdict::Allow);
                match v {
                    Verdict::Allow => {
                        if upstream.write_all(chunk).is_err() {
                            return;
                        }
                    }
                    _ => {
                        tarpit(&mut client);
                        return;
                    }
                }
            }
        }
        let _ = upstream.set_read_timeout(Some(Duration::from_millis(0)));
        match upstream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(_) => {}
        }
    }
}

fn run_guard(pairs: &[String]) {
    let fw = Arc::new(Mutex::new(firewall()));
    for pair in pairs {
        let mut it = pair.split(':');
        let (lp, tp) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(b), Some(c)) => (format!("{a}:{b}"), c.to_string()),
            (Some(a), Some(b), None) => (format!("0.0.0.0:{a}"), format!("127.0.0.1:{b}")),
            _ => continue,
        };
        let listen_port = lp
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(9101);
        let fw = Arc::clone(&fw);
        std::thread::spawn(move || {
            while !STOP.load(Ordering::Relaxed) {
                let listener = match TcpListener::bind(&lp) {
                    Ok(l) => l,
                    Err(_) => {
                        std::thread::sleep(Duration::from_secs(5));
                        continue;
                    }
                };
                listener
                    .set_nonblocking(true)
                    .ok();
                loop {
                    if STOP.load(Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok((s, _)) => {
                            let fw = Arc::clone(&fw);
                            let tp = tp.clone();
                            std::thread::spawn(move || handle(s, &tp, listen_port, &fw));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => break,
                    }
                }
            }
        });
    }
}

fn service_main(_args: Vec<OsString>) {
    let status_handle = match service_control_handler::register("SwarmShieldSE", |event| {
        match event {
            ServiceControl::Stop => {
                STOP.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(h) => h,
        Err(_) => return,
    };
    let report = |state: ServiceState, wait_hint: u32| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_millis(wait_hint as u64),
            process_id: None,
        });
    };
    report(ServiceState::StartPending, 10_000);

    let pairs: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let pairs = if pairs.is_empty() {
        vec!["9101:8081".to_string()]
    } else {
        pairs
    };
    run_guard(&pairs);
    report(ServiceState::Running, 0);

    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
    }
    report(ServiceState::StopPending, 5_000);
    std::thread::sleep(Duration::from_secs(1));
    report(ServiceState::Stopped, 0);
}

fn main() -> windows_service::Result<()> {
    service_dispatcher::start("SwarmShieldSE", ffi_service_main)
}
