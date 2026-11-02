use std::net::{IpAddr, Ipv4Addr};

use snn_firewall::{MitigationKind, MitigationRule, PolicySink, RuleSubject};
use snn_runtime::{FilePolicySink, PolicyDocument};

fn rule(id: u64, kind: MitigationKind) -> MitigationRule {
    MitigationRule {
        id,
        subject: RuleSubject::Ip(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        kind,
        created_ms: 1000,
        expires_ms: 61_000,
        offense: 1,
        reason: "test".into(),
    }
}

#[test]
fn file_sink_writes_atomic_policy_doc() {
    let dir = std::env::temp_dir().join(format!("snn-sink-{}", std::process::id()));
    let mut sink = FilePolicySink::new(&dir);

    sink.apply(&rule(1, MitigationKind::Drop)).unwrap();
    sink.apply(&rule(2, MitigationKind::RateLimit { max_rps: 25.0 }))
        .unwrap();

    let doc: PolicyDocument =
        serde_json::from_str(&std::fs::read_to_string(dir.join("policy.json")).unwrap()).unwrap();
    assert_eq!(doc.rules.len(), 2);
    assert_eq!(doc.rules[0].subject, "ip:9.9.9.9");
    assert_eq!(doc.rules[0].action, "drop");
    assert_eq!(doc.rules[1].action, "rate_limit");
    assert_eq!(doc.rules[1].max_rps, Some(25.0));

    sink.revoke(1).unwrap();
    let doc: PolicyDocument =
        serde_json::from_str(&std::fs::read_to_string(dir.join("policy.json")).unwrap()).unwrap();
    assert_eq!(doc.rules.len(), 1);
    assert_eq!(doc.rules[0].id, 2);

    std::fs::remove_dir_all(&dir).ok();
}

/// ureq's wire contract: PUT /rules/{id} on apply, DELETE on revoke —
/// verified against a real TCP listener, no mock.
#[cfg(feature = "http-sink")]
#[test]
fn http_sink_pushes_put_and_delete() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use snn_runtime::{HttpPolicySink, ProxyRule};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut s = stream.unwrap();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap(); // request line
            let mut content_length = 0usize;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            tx.send(format!(
                "{}|{}",
                line.trim(),
                String::from_utf8_lossy(&body)
            ))
            .unwrap();
            write!(s, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
        }
    });

    let mut sink = HttpPolicySink::new(format!("http://127.0.0.1:{port}"));
    sink.apply(&rule(7, MitigationKind::Drop)).unwrap();
    sink.revoke(7).unwrap();

    let apply = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(apply.starts_with("PUT /rules/7"), "got: {apply}");
    let body: ProxyRule = serde_json::from_str(apply.split('|').nth(1).unwrap()).unwrap();
    assert_eq!(body.action, "drop");
    assert_eq!(body.expires_ms, 61_000);

    let revoke = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(revoke.starts_with("DELETE /rules/7"), "got: {revoke}");
}
