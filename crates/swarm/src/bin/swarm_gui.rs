//! `swarm_gui` — the SwarmShieldSE desktop app. Real Win32 window,
//! dark-themed to match the product: live status, detection feed,
//! one-button protection toggle, and token activation.

#![cfg(windows)]
#![windows_subsystem = "windows"] // GUI app — no console window

use native_windows_gui as nwg;

const FEED: &str = r"C:\ProgramData\SwarmShieldSE\svc_feed.log";
// Buy/activate page — swap to https://swarmshieldse.com when live (.com
// over .au — global reach, no geo signal).
const SIGNUP_URL: &str = "http://127.0.0.1:8080/signup";
// Site palette
const BG: [u8; 3] = [13, 17, 23]; // #0d1117
const FG: [u8; 3] = [230, 237, 243]; // #e6edf3
const DIM: [u8; 3] = [139, 148, 158]; // #8b949e
const GREEN: [u8; 3] = [63, 185, 80]; // #3fb950

fn service_running() -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW — no console flash
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
        .unwrap_or_else(|| vec!["  feed is quiet — nothing blocked yet".into()])
}

fn font(size: u32, bold: bool) -> nwg::Font {
    let mut f: nwg::Font = Default::default();
    nwg::Font::builder()
        .family("Segoe UI")
        .size(size)
        .weight(if bold { 700 } else { 400 })
        .build(&mut f)
        .ok();
    f
}

fn main() {
    // GUI app has no console — dump panics to a log so crashes are debuggable.
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write(
            r"C:\Users\Black\Desktop\SNN\gui_crash.log",
            format!("{info}\n{:?}", std::backtrace::Backtrace::force_capture()),
        );
    }));
    nwg::init().expect("nwg init failed");

    let mut window = Default::default();
    let mut title: nwg::Label = Default::default();
    let mut sub: nwg::Label = Default::default();
    let mut status: nwg::Label = Default::default();
    let mut feed_title: nwg::Label = Default::default();
    let mut feed: nwg::ListBox<String> = Default::default();
    let mut toggle: nwg::Button = Default::default();
    let mut tok_box: nwg::TextInput = Default::default();
    let mut btn_act: nwg::Button = Default::default();
    let mut timer = Default::default();

    nwg::Window::builder()
        .size((660, 540))
        .title("SwarmShieldSE")
        .build(&mut window)
        .unwrap();

    // Header
    nwg::Label::builder()
        .text("SwarmShieldSE")
        .position((24, 20))
        .size((400, 30))
        .font(Some(&font(28, true)))
        .parent(&window)
        .build(&mut title)
        .unwrap();
    nwg::Label::builder()
        .text("the firewall that learns — pure Rust, runs locally")
        .position((26, 56))
        .size((440, 20))
        .font(Some(&font(17, false)))
        .parent(&window)
        .build(&mut sub)
        .unwrap();

    // Status line
    nwg::Label::builder()
        .text("status: checking…")
        .position((26, 92))
        .size((560, 24))
        .font(Some(&font(20, false)))
        .parent(&window)
        .build(&mut status)
        .unwrap();

    // Feed
    nwg::Label::builder()
        .text("blocked-event feed")
        .position((26, 128))
        .size((300, 18))
        .font(Some(&font(15, true)))
        .parent(&window)
        .build(&mut feed_title)
        .unwrap();
    nwg::ListBox::builder()
        .position((24, 152))
        .size((612, 270))
        .collection(vec!["  loading…".to_string()])
        .font(Some(&font(15, false)))
        .parent(&window)
        .build(&mut feed)
        .unwrap();

    // Controls row
    nwg::Button::builder()
        .text("Protection: ON")
        .position((24, 438))
        .size((180, 44))
        .font(Some(&font(17, true)))
        .parent(&window)
        .build(&mut toggle)
        .unwrap();
    nwg::TextInput::builder()
        .position((220, 444))
        .size((270, 32))
        .placeholder_text(Some("SS-SE-XXXX-XXXX"))
        .font(Some(&font(15, false)))
        .parent(&window)
        .build(&mut tok_box)
        .unwrap();
    nwg::Button::builder()
        .text("Activate Pro")
        .position((498, 438))
        .size((138, 44))
        .font(Some(&font(15, false)))
        .parent(&window)
        .build(&mut btn_act)
        .unwrap();

    nwg::AnimationTimer::builder()
        .interval(std::time::Duration::from_secs(2))
        .parent(&window)
        .build(&mut timer)
        .unwrap();
    timer.start();

    let cache = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
    let cache_cb = cache.clone();

    let _handler = nwg::bind_event_handler(&window.handle, &window.handle, move |evt, _d, h| {
        use nwg::Event as E;
        match evt {
            E::OnTimerTick if h == timer.handle => {
                let on = service_running();
                status.set_text(if on {
                    "●  PROTECTED — the guard is watching"
                } else {
                    "○  not running — flip the switch below"
                });
                toggle.set_text(if on { "Protection: ON" } else { "Protection: OFF" });
                let items = read_feed();
                let mut c = cache_cb.borrow_mut();
                if *c != items {
                    *c = items.clone();
                    feed.set_collection(items);
                }
            }
            E::OnButtonClick if h == toggle => {
                let cmd = if service_running() { "stop" } else { "start" };
                // sc needs admin — elevate via Start-Process so a UAC
                // prompt appears instead of a silent failure.
                let _ = std::process::Command::new("powershell")
                    .args([
                        "-Command",
                        &format!(
                            "Start-Process sc -Verb RunAs -ArgumentList '{cmd} SwarmShieldSE'"
                        ),
                    ])
                    .status();
            }
            E::OnButtonClick if h == btn_act => {
                let tok = tok_box.text();
                if !tok.is_empty() {
                    let _ = std::process::Command::new("swarmshield.exe")
                        .args(["--activate", &tok])
                        .status();
                    status.set_text("activating — checking your token…");
                } else {
                    // No token pasted → open the buy page.
                    let _ = std::process::Command::new("cmd")
                        .args(["/c", "start", SIGNUP_URL])
                        .status();
                }
            }
            E::OnWindowClose => nwg::stop_thread_dispatch(),
            _ => {}
        }
    });

    nwg::dispatch_thread_events();
}
