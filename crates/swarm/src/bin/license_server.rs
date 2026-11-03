//! `license-server` — reference licensing backend for SwarmShieldSE.
//! JSON-file store (swap for Postgres/Stripe webhooks in prod — the API
//! surface is the contract, not the storage).
//!
//! Endpoints (all GET for the reference impl):
//!   /verify?token=X&mid=Y   → "active" | "expired" | "bound_elsewhere" | "invalid"
//!   /activate?token&email&mid → binds token→email+machine; "active" | "bound_elsewhere"
//!   /issue?email=E&days=N    → new token line "SS-SE-XXXXXXXX <token>"
//!   /forgot?email=E          → revoke+reissue → new token
//!
//! Prod flow: Stripe webhook → /issue → email token → client /activate
//! → periodic /verify (48h offline grace client-side).

use ed25519_dalek::{Signer, SigningKey};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Dev signing key — deterministic from a fixed seed so the client's
/// baked-in public key verifies it. Prod: env var or HSM, never baked.
fn signing_key() -> SigningKey {
    let seed = std::env::var("SWARM_SIGN_SEED")
        .map(|s| {
            let mut h = [0u8; 32];
            for (i, b) in s.bytes().cycle().take(32).enumerate() {
                h[i] ^= b;
            }
            h
        })
        .unwrap_or_else(|_| {
            // dev seed — the matching pub key lives in swarmshield.rs
            let mut s = [0x55u8; 32];
            for (i, b) in b"swarmshield-dev-signing-seed".iter().enumerate() {
                s[i % 32] ^= *b;
            }
            s
        });
    SigningKey::from_bytes(&seed)
}

/// Sign the grant — `token|expiry|mid` — only the private key can.
fn grant_sig(token: &str, expiry: u64, mid: u64) -> String {
    let msg = format!("{token}|{expiry}|{mid:x}");
    signing_key()
        .sign(msg.as_bytes())
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone)]
struct Lic {
    token: String,
    email: String,
    mid: u64,
    expires: u64,
    revoked: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn store_path() -> String {
    std::env::var("SWARM_LICENSE_DB").unwrap_or_else(|_| "licenses.json".into())
}

fn load() -> Vec<Lic> {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(db: &[Lic]) {
    let _ = std::fs::write(store_path(), serde_json::to_string_pretty(db).unwrap());
}

fn gen_token(email: &str, n: usize) -> String {
    let s = format!("{email}:{n}:{}", now());
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("SS-SE-{h:016X}")
}

fn param<'a>(q: &'a str, k: &str) -> Option<String> {
    q.split('&')
        .find_map(|p| p.split_once('=').filter(|(a, _)| *a == k).map(|(_, v)| v.to_string()))
}

fn route(path: &str, db: &Mutex<Vec<Lic>>) -> String {
    let q = path.split('?').nth(1).unwrap_or("");
    let get = |k: &str| param(q, k).unwrap_or_default();
    let mid_of = |m: Option<String>| m.and_then(|m| u64::from_str_radix(&m, 16).ok()).unwrap_or(0);
    if path.starts_with("/verify") {
        let (tok, mid) = (get("token"), mid_of(param(q, "mid")));
        let db = db.lock().unwrap();
        match db.iter().find(|l| l.token == tok && !l.revoked) {
            Some(l) if l.mid != 0 && l.mid != mid => "bound_elsewhere".into(),
            // Failed-payment grace: expired <3d still active, flagged.
            Some(l) if l.expires < now() && l.expires + 3 * 86400 >= now() => "grace".into(),
            Some(l) if l.expires < now() => "expired".into(),
            Some(l) => format!("active|{}", grant_sig(&tok, l.expires, mid)),
            None => "invalid".into(),
        }
    } else if path.starts_with("/activate") {
        let (tok, email, mid) = (get("token"), get("email"), mid_of(param(q, "mid")));
        let mut db = db.lock().unwrap();
        match db.iter_mut().find(|l| l.token == tok && !l.revoked) {
            Some(l) if l.mid != 0 && l.mid != mid => "bound_elsewhere".into(),
            Some(l) => {
                l.mid = mid;
                if l.email.is_empty() {
                    l.email = email;
                }
                save(&db);
                "active".into()
            }
            None => "invalid".into(),
        }
    } else if path.starts_with("/transfer") {
        // Seat transfer: rebind to a NEW machine (deactivates the old
        // one) — same email required so strangers can't steal the seat.
        let (tok, email, mid) = (get("token"), get("email"), mid_of(param(q, "mid")));
        let mut db = db.lock().unwrap();
        match db.iter_mut().find(|l| l.token == tok && !l.revoked && l.email == email) {
            Some(l) => {
                l.mid = mid;
                save(&db);
                "transferred".into()
            }
            None => "invalid".into(),
        }
    } else if path.starts_with("/issue") {
        let email = get("email");
        let days: u64 = get("days").parse().unwrap_or(7);
        let mut db = db.lock().unwrap();
        let tok = gen_token(&email, db.len());
        db.push(Lic {
            token: tok.clone(),
            email,
            mid: 0,
            expires: now() + days * 86400,
            revoked: false,
        });
        save(&db);
        tok
    } else if path.starts_with("/forgot") {
        let email = get("email");
        let mut db = db.lock().unwrap();
        for l in db.iter_mut().filter(|l| l.email == email) {
            l.revoked = true;
        }
        let tok = gen_token(&email, db.len());
        db.push(Lic {
            token: tok.clone(),
            email,
            mid: 0,
            expires: now() + 7 * 86400,
            revoked: false,
        });
        save(&db);
        tok
    } else if path.starts_with("/report") {
        // Herd-immunity push: a client's discovered playbook entry
        // (shape_key:fix_kind) lands in the shared feed. Zero telemetry
        // — the entry is just a shape string + a mitigation kind.
        let entry = get("entry")
            .replace("%3A", ":")
            .replace("%3B", ";")
            .replace("%28", "(")
            .replace("%29", ")")
            .replace("%3D", "=");
        let db = db.lock().unwrap();
        // Feed entries live alongside licenses in the same store file —
        // prod splits this; the contract is the API.
        let feed_path = std::env::var("SWARM_FEED_FILE").unwrap_or_else(|_| "feed.txt".into());
        let mut feed: Vec<String> = std::fs::read_to_string(&feed_path)
            .map(|s| s.lines().map(String::from).collect())
            .unwrap_or_default();
        if !entry.is_empty() && !feed.contains(&entry) {
            feed.push(entry);
            let _ = std::fs::write(&feed_path, feed.join("\n"));
        }
        drop(db);
        "ok".into()
    } else if path.starts_with("/feed") {
        let feed_path = std::env::var("SWARM_FEED_FILE").unwrap_or_else(|_| "feed.txt".into());
        std::fs::read_to_string(feed_path).unwrap_or_default()
    } else if path.starts_with("/crash") {
        "ok".into()
    } else {
        "endpoints: /verify /activate /issue /forgot /report /feed /crash".into()
    }
}

// serde impls for Lic — tiny manual, no derive needed
impl serde::Serialize for Lic {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Lic", 5)?;
        st.serialize_field("token", &self.token)?;
        st.serialize_field("email", &self.email)?;
        st.serialize_field("mid", &self.mid)?;
        st.serialize_field("expires", &self.expires)?;
        st.serialize_field("revoked", &self.revoked)?;
        st.end()
    }
}
impl<'de> serde::Deserialize<'de> for Lic {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Raw {
            token: String,
            email: String,
            mid: u64,
            expires: u64,
            revoked: bool,
        }
        let r = Raw::deserialize(d)?;
        Ok(Lic {
            token: r.token,
            email: r.email,
            mid: r.mid,
            expires: r.expires,
            revoked: r.revoked,
        })
    }
}

fn main() {
    swarm::crash::install();
    let listen = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:9100".into());
    let db = Mutex::new(load());
    eprintln!("[licenses] {listen} — {} entries loaded", db.lock().unwrap().len());
    for s in TcpListener::bind(&listen).unwrap().incoming().flatten() {
        let db = &db;
        std::thread::scope(|_| {
            let mut s = s;
            let mut buf = [0u8; 4096];
            if let Ok(n) = s.read(&mut buf) {
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                if path.starts_with("/crash") {
                    // Anonymous crash ping — append the POST body only.
                    if let Some(b) = req.split("\r\n\r\n").nth(1) {
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("crashes.log")
                            .and_then(|mut f| std::io::Write::write_all(&mut f, b.as_bytes()));
                    }
                }
                let body = route(path, db);
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
    }
}
