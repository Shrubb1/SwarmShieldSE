//! `swarm_gui` — SwarmShieldSE desktop app. WebView2 window (wry) —
//! the real dark theme, matching the site: live status, detection
//! feed, one-button protection toggle, token activation.
//!
//! IPC: the page calls `ipc.postMessage({cmd})` — toggle runs `sc`
//! (the app is already elevated via manifest), activate runs
//! `swarmshield.exe --activate TOK`. Status+feed push in via eval.

#![cfg(windows)]
#![windows_subsystem = "windows"]

use std::os::windows::process::CommandExt;
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::{http::{Request, Response}, WebViewBuilder};
use std::borrow::Cow;

const FEED: &str = r"C:\ProgramData\SwarmShieldSE\svc_feed.log";
const NO_WINDOW: u32 = 0x08000000;

fn service_running() -> bool {
    std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(NO_WINDOW)
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("swarm_svc.exe") || s.contains("swarmshield.exe")
        })
        .unwrap_or(false)
}

fn feed_lines() -> Vec<String> {
    // Merge every log source — blocks, scanner, watcher, ads — so the
    // app shows everything happening live, most recent last.
    let mut all: Vec<String> = Vec::new();
    for f in [
        FEED,
        r"C:\ProgramData\SwarmShieldSE\scan_log.txt",
        r"C:\ProgramData\SwarmShieldSE\watcher_log.txt",
        r"C:\ProgramData\SwarmShieldSE\ads_log.txt",
    ] {
        if let Ok(s) = std::fs::read_to_string(f) {
            let label = match f {
                x if x.contains("scan_log") => "[scan]",
                x if x.contains("watcher") => "[watch]",
                x if x.contains("ads") => "[ad-block]",
                _ => "[block]",
            };
            for l in s.lines().rev().take(6) {
                all.push(format!("{label} {l}"));
            }
        }
    }
    if all.is_empty() {
        vec!["feed is quiet — nothing blocked yet".into()]
    } else {
        all.reverse();
        all.truncate(20);
        all
    }
}

const HTML: &str = include_str!("../../gui.html");
const LAST_SCAN: &str = r"C:\ProgramData\SwarmShieldSE\last_scan.txt";
const WEEK_MS: u64 = 7 * 24 * 3600 * 1000;

fn proc_running(name: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(name))
        .unwrap_or(false)
}

fn spawn_no_console(exe: &str, args: &[&str]) {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    let _ = std::process::Command::new(dir.join(exe))
        .args(args)
        .creation_flags(NO_WINDOW)
        .spawn();
}

/// On launch: spawn the bundled pieces. Ad-block (dns_guard) is free
/// and always-on; the scanner auto-runs weekly on the free tier.
fn start_aux() {
    if !proc_running("dns_guard.exe") {
        spawn_no_console("dns_guard.exe", &[]);
    }
    if !proc_running("swarm_watcher.exe") {
        spawn_no_console("swarm_watcher.exe", &[]);
    }
    let last = std::fs::read_to_string(LAST_SCAN)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if now - last > WEEK_MS && !proc_running("swarm_scanner.exe") {
        spawn_no_console("swarm_scanner.exe", &[r"C:\Users"]);
        let _ = std::fs::write(LAST_SCAN, now.to_string());
    }
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write(r"C:\Users\Black\Desktop\SNN\gui_crash.log", info.to_string());
    }));

    start_aux();
    let el: EventLoop<()> = EventLoop::new();
    let proxy = el.create_proxy();
    // Window/taskbar icon — the tight square shield as RGBA.
    let png = image::load_from_memory(include_bytes!("../../../../site/assets/logo_sq.png"))
        .unwrap()
        .to_rgba8();
    let (iw, ih) = png.dimensions();
    let win_icon = tao::window::Icon::from_rgba(png.into_raw(), iw, ih).ok();

    let window = WindowBuilder::new()
        .with_title("SwarmShieldSE")
        .with_inner_size(tao::dpi::LogicalSize::new(680.0, 560.0))
        .with_window_icon(win_icon)
        .build(&el)
        .unwrap();

    let wv = WebViewBuilder::new()
        .with_html(HTML)
        .with_custom_protocol("swarm".into(), |_id, _req| {
            Response::builder()
                .header("Content-Type", "image/png")
                .body(Cow::Borrowed(&include_bytes!("../../../../site/assets/logo_sq.png")[..]))
                .unwrap()
        })
        .with_ipc_handler(move |req: Request<String>| {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(req.body()) {
                match v.get("cmd").and_then(|c| c.as_str()) {
                    Some("toggle") => {
                        let cmd = if service_running() { "stop" } else { "start" };
                        let _ = std::process::Command::new("sc")
                            .args([cmd, "SwarmShieldSE"])
                            .creation_flags(NO_WINDOW)
                            .status();
                    }
                    Some("scan") => {
                        // Pro-gated: only run on-demand if a signed
                        // grant cache exists. Free tier = weekly auto.
                        let pro = std::env::var("USERPROFILE")
                            .map(|p| std::path::Path::new(&format!("{p}\\.swarmshield-license")).exists())
                            .unwrap_or(false);
                        if pro && !proc_running("swarm_scanner.exe") {
                            spawn_no_console("swarm_scanner.exe", &[r"C:\Users"]);
                        }
                    }
                    Some("activate") => {
                        let tok = v.get("token").and_then(|t| t.as_str()).unwrap_or("");
                        if !tok.is_empty() {
                            let _ = std::process::Command::new("swarmshield.exe")
                                .args(["--activate", tok])
                                .creation_flags(NO_WINDOW)
                                .status();
                        } else {
                            let _ = std::process::Command::new("cmd")
                                .args(["/c", "start", "http://127.0.0.1:8080/signup"])
                                .creation_flags(NO_WINDOW)
                                .status();
                        }
                    }
                    _ => {}
                }
            }
        })
        .build(&window)
        .unwrap();

    // Status tick: a thread pings the loop every 2s → evaluate_script.
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = proxy.send_event(());
    });

    el.run(move |event, _, cf| {
        *cf = ControlFlow::Wait;
        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            Event::UserEvent(()) => {
                let on = service_running();
                let feed = feed_lines().join("<br>");
                let js = format!(
                    "upd({}, `{}`)",
                    on,
                    feed.replace('\\', "\\\\").replace('`', "\\`")
                );
                let _ = wv.evaluate_script(&js);
            }
            _ => {}
        }
    });
}
