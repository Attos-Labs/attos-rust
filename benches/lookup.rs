//! Lookup benchmarks. Run with `cargo bench`.
//!
//! * `lookup/golden_1000`: the 1,000 keys of the checked-in golden file `tests/golden/golden_v2_1000.attos`
//!   (always available).
//! * `lookup/hot_1k` and `lookup/random_1M` need a larger file: set `ATTOS_BENCH_FILE` to a v2 file built from
//!   keys `user_<i>\0category_<i%100>\0region_<i%50>` (i in 0..ATTOS_BENCH_KEYS, default 1,000,000) and values `<i>`,
//!   for example with the Go SDK builder (see `benchmarks/` in the attos-cloud repository). The file is read once
//!   before timing so everything is in the page cache: these numbers are cached lookups, not cold-start or
//!   whole-file-in-RAM-pressure numbers.
use attos_client::AttosMap;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::PathBuf;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn key(i: usize) -> Vec<u8> {
    format!("user_{i}\0category_{}\0region_{}", i % 100, i % 50).into_bytes()
}

fn golden(c: &mut Criterion) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let map = AttosMap::open(dir.join("golden_v2_1000.attos")).unwrap();
    let keys: Vec<Vec<u8>> = std::fs::read_to_string(dir.join("golden_v2_1000.tsv"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| unhex(l.split_once('\t').map(|p| p.0).unwrap_or(l)))
        .collect();
    let mut i = 0usize;
    c.bench_function("lookup/golden_1000", |b| {
        b.iter(|| {
            i = (i + 1) % keys.len();
            black_box(map.get(black_box(&keys[i])).unwrap());
        })
    });
}

fn big(c: &mut Criterion) {
    let Ok(path) = std::env::var("ATTOS_BENCH_FILE") else {
        eprintln!("ATTOS_BENCH_FILE not set: skipping lookup/hot_1k and lookup/random_1M");
        return;
    };
    let n: usize = std::env::var("ATTOS_BENCH_KEYS").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    let map = AttosMap::open(&path).unwrap();
    // pull the whole file into the page cache so the benchmark measures lookups, not disk reads
    let _ = std::fs::read(&path).map(|b| black_box(b.len()));

    let mut state = 0x9E3779B97F4A7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let hot: Vec<Vec<u8>> = (0..1000).map(|_| key((next() % n as u64) as usize)).collect();
    let random: Vec<Vec<u8>> = (0..1 << 20).map(|_| key((next() % n as u64) as usize)).collect();
    for k in hot.iter().chain(random.iter().take(1000)) {
        map.get(k).expect("key missing: is ATTOS_BENCH_FILE built with the documented keys?");
    }

    let mut i = 0usize;
    c.bench_function("lookup/hot_1k", |b| {
        b.iter(|| {
            i = (i + 1) % hot.len();
            black_box(map.get(black_box(&hot[i])).unwrap());
        })
    });
    let mut j = 0usize;
    c.bench_function("lookup/random_1M", |b| {
        b.iter(|| {
            j = (j + 1) & (random.len() - 1);
            black_box(map.get(black_box(&random[j])).unwrap());
        })
    });
}

criterion_group!(benches, golden, big);
criterion_main!(benches);
