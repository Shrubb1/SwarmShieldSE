//! `swarm_gui` — the SwarmShieldSE desktop app. Real Win32 window:
//! live protection status, the detection feed, and service controls.
//! No webview — native widgets via native-windows-gui.

#![cfg(windows)]

use native_windows_gui as nwg;

const FEED: &str = r"C:\ProgramData\SwarmShieldSE\svc_feed.log";

fn service_running() -> bool {
    std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("swarm_svc.exe") || s.contains("swarmshield.exe")
        })
        .unwrap_or(false)
}

fn read_feed() -> Vec<String> {
    std::fs::read_to_string(FEED)
        .ok()
        .map(|s| s.lines().map(|l| l.to_string()).collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["(no blocked events yet — feed is quiet)".into()])
}

fn main() {
    nwg::init().expect("nwg init failed");

    let mut window = Default::default();
    let mut status = Default::default();
    let mut feed: nwg::ListBox<String> = Default::default();
    let mut btn_start = Default::default();
    let mut btn_stop: nwg::Button = Default::default();
    let mut timer = Default::default();

    nwg::Window::builder()
        .size((600, 480))
        .title("SwarmShieldSE")
        .build(&mut window)
        .unwrap();

    let mut title: nwg::Label = Default::default();
    nwg::Label::builder()
        .text("SwarmShieldSE — behavioral firewall")
        .position((18, 14))
        .size((560, 22))
        .parent(&window)
        .build(&mut title)
        .unwrap();

    nwg::Label::builder()
        .text("status: checking…")
        .position((18, 42))
        .size((560, 22))
        .parent(&window)
        .build(&mut status)
        .unwrap();

    nwg::ListBox::builder()
        .position((18, 74))
        .size((564, 320))
        .collection(vec!["loading…".to_string()])
        .parent(&window)
        .build(&mut feed)
        .unwrap();

    // One big toggle — protection on/off without uninstalling.
    let mut toggle: nwg::Button = Default::default();
    nwg::Button::builder()
        .text("Turn protection OFF")
        .position((18, 404))
        .size((200, 40))
        .parent(&window)
        .build(&mut toggle)
        .unwrap();

    // Activation: paste a token, hit Activate → signed-grant path.
    let mut tok_box: nwg::TextInput = Default::default();
    nwg::TextInput::builder()
        .position((236, 404))
        .size((240, 32))
        .placeholder_text(Some("SS-SE-XXXX-XXXX (activation token)"))
        .parent(&window)
        .build(&mut tok_box)
        .unwrap();
    nwg::Button::builder()
        .text("Activate Pro")
        .position((484, 404))
        .size((98, 36))
        .parent(&window)
        .build(&mut btn_start)
        .unwrap();
    let _ = &mut btn_stop;

    nwg::AnimationTimer::builder()
        .interval(std::time::Duration::from_secs(2))
        .parent(&window)
        .build(&mut timer)
        .unwrap();
    timer.start();

    let feed_items = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
    let feed_items_cb = feed_items.clone();

    nwg::bind_event_handler(&window.handle, &window.handle, move |evt, _d, h| {
        use nwg::Event as E;
        match evt {
            E::OnTimerTick if h == timer.handle => {
                status.set_text(if service_running() {
                    "● status: PROTECTED — the guard is running"
                } else {
                    "○ status: not running — start it or reinstall"
                });
                let items = read_feed();
                let mut cache = feed_items_cb.borrow_mut();
                if *cache != items {
                    *cache = items.clone();
                    feed.set_collection(items);
                }
                // Flip the toggle label to match live state.
                toggle.set_text(if service_running() {
                    "Turn protection OFF"
                } else {
                    "Turn protection ON"
                });
            }
            // The toggle: one button flips the service on/off.
            E::OnButtonClick if h == toggle => {
                let cmd = if service_running() { "stop" } else { "start" };
                let _ = std::process::Command::new("sc")
                    .args([cmd, "SwarmShieldSE"])
                    .status();
            }
            // Activate: hand the token to swarmshield's signed path.
            E::OnButtonClick if h == btn_start => {
                let tok = tok_box.text();
                if !tok.is_empty() {
                    let _ = std::process::Command::new("swarmshield.exe")
                        .args(["--activate", &tok])
                        .status();
                    status.set_text("activating — token sent to license server…");
                }
            }
            E::OnButtonClick if h == btn_stop => {
                let _ = std::process::Command::new("sc")
                    .args(["stop", "SwarmShieldSE"])
                    .status();
            }
            E::OnWindowClose => nwg::stop_thread_dispatch(),
            _ => {}
        }
    });

    nwg::dispatch_thread_events();
}
