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
    std::fs::read_to_string(FEED)
        .ok()
        .map(|s| s.lines().map(|l| l.to_string()).collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .unwrap_or_default()
}

const HTML: &str = include_str!("../../gui.html");

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write(r"C:\Users\Black\Desktop\SNN\gui_crash.log", info.to_string());
    }));

    let el: EventLoop<()> = EventLoop::new();
    let proxy = el.create_proxy();
    let window = WindowBuilder::new()
        .with_title("SwarmShieldSE")
        .with_inner_size(tao::dpi::LogicalSize::new(680.0, 560.0))
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
