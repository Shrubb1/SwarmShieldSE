//! Live Postgres integration for `PostgresStore`.
//!
//! Gated twice: needs `--features postgres-store` AND `SNN_TEST_PG` set to a
//! connection string (e.g. `postgres://user:pw@localhost/snn_test`). Without
//! a live DB the test prints a skip line and passes, so `cargo test` stays
//! green on machines without Postgres.
//!
//! Run it live:
//!   SNN_TEST_PG="postgres://postgres:postgres@localhost/postgres" \
//!     cargo test -p snn-mesh --features postgres-store -- --nocapture

#![cfg(feature = "postgres-store")]

use snn_mesh::{CheckpointStore, PostgresStore};

fn conn_str() -> Option<String> {
    std::env::var("SNN_TEST_PG").ok().filter(|s| !s.is_empty())
}

#[test]
fn postgres_store_round_trip() {
    let Some(conn) = conn_str() else {
        eprintln!("SNN_TEST_PG unset — skipping live Postgres test");
        return;
    };

    let name = format!("snn-test-{}", std::process::id());
    let store = PostgresStore::connect(&conn, name).expect("connect + create table");

    // First boot → empty.
    assert!(store.load().unwrap().is_none());

    // Save + load round-trip through the bytea column.
    let v1 = b"checkpoint-v1: weights, traces, delay queue".to_vec();
    store.save(&v1, 100).unwrap();
    assert_eq!(store.load().unwrap().as_deref(), Some(v1.as_slice()));

    // Upsert overwrites, not appends: same name → latest only.
    let v2 = vec![0xABu8; 4096];
    store.save(&v2, 200).unwrap();
    assert_eq!(store.load().unwrap().as_deref(), Some(v2.as_slice()));

    // A second store on the same row sees the same memory (two workers,
    // one brain — or rather, sequential incarnations of one worker).
    let store2 = PostgresStore::connect(&conn, format!("snn-test-{}", std::process::id())).unwrap();
    assert_eq!(store2.load().unwrap().as_deref(), Some(v2.as_slice()));

    // Clean up our row so the test doesn't pollute the schema.
    let mut client = postgres::Client::connect(&conn, postgres::NoTls).unwrap();
    client
        .execute(
            "DELETE FROM snn_checkpoints WHERE name LIKE 'snn-test-%'",
            &[],
        )
        .unwrap();
}
