#![allow(dead_code)]
//! Shared test helpers: golden-fixture discovery and a tiny test-only blob
//! builder implementing the canonical CONTRACTS §1.3–1.4 placement.
use std::hash::Hasher;
use std::path::PathBuf;
use twox_hash::XxHash64;

/// $GOLDEN_DIR, else ../testdata/golden (main checkout) or
/// ../../../../testdata/golden (track worktree). None → caller skips.
pub fn golden_dir() -> Option<PathBuf> {
    let mut c: Vec<PathBuf> = Vec::new();
    if let Ok(d) = std::env::var("GOLDEN_DIR") {
        c.push(d.into());
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    c.push(here.join("../testdata/golden"));
    c.push(here.join("../../../../testdata/golden"));
    let found = c.iter().find(|d| d.join("MANIFEST.md").is_file()).cloned();
    if found.is_none() {
        eprintln!("SKIPPING golden tests: fixtures not found (set GOLDEN_DIR; tried {:?})", c);
    }
    found
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hash(k: &[u8]) -> u64 {
    let mut h = XxHash64::with_seed(0);
    h.write(k);
    h.finish()
}

fn is_prime(n: u64) -> bool {
    if n < 2 { return false; }
    if n < 4 { return true; }
    if n % 2 == 0 || n % 3 == 0 { return false; }
    let mut i = 5;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 { return false; }
        i += 6;
    }
    true
}

/// Build a v1 blob from unique (key, value) rows.
pub fn build(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let n = rows.len() as u64;
    let mut s = (n * 12 / 10).max(3);
    while !is_prime(s) { s += 1; }
    let b = (s * 6 / 5).max(1);
    let mut buckets: Vec<Vec<(u64, usize)>> = vec![Vec::new(); b as usize];
    for (i, (k, _)) in rows.iter().enumerate() {
        let h = hash(k);
        buckets[((h >> 32) as u32 as u64 % b) as usize].push((h as u32 as u64, i));
    }
    let mut order: Vec<usize> = (0..b as usize).filter(|&i| !buckets[i].is_empty()).collect();
    order.sort_by(|&x, &y| buckets[y].len().cmp(&buckets[x].len()).then(x.cmp(&y)));
    let mut slot_row = vec![usize::MAX; s as usize];
    let mut disp = vec![0u32; b as usize];
    for bi in order {
        let mut d = 0u64;
        'search: loop {
            let mut used = Vec::new();
            for &(lo, _) in &buckets[bi] {
                let sl = ((lo ^ d) % s) as usize;
                if slot_row[sl] != usize::MAX || used.contains(&sl) {
                    d += 1;
                    continue 'search;
                }
                used.push(sl);
            }
            for (j, &(_, r)) in buckets[bi].iter().enumerate() {
                slot_row[used[j]] = r;
            }
            disp[bi] = d as u32;
            break;
        }
    }
    let wide = disp.iter().any(|&d| d > 0xFFFF);
    let mut out = Vec::new();
    out.extend_from_slice(b"ATTO");
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(if wide { 2 } else { 1 });
    out.extend_from_slice(&s.to_be_bytes());
    out.extend_from_slice(&b.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    for d in &disp {
        if wide { out.extend_from_slice(&d.to_be_bytes()) } else { out.extend_from_slice(&(*d as u16).to_be_bytes()) }
    }
    let mut data = Vec::new();
    for &r in &slot_row {
        if r == usize::MAX {
            out.extend_from_slice(&0u64.to_be_bytes());
            continue;
        }
        let (k, v) = &rows[r];
        let off = data.len() as u64;
        data.extend_from_slice(&(k.len() as u16).to_be_bytes());
        data.extend_from_slice(k);
        data.extend_from_slice(v);
        out.extend_from_slice(&((off << 32) | (data.len() as u64 - off)).to_be_bytes());
    }
    out.extend_from_slice(&data);
    let mut c = crc32fast::Hasher::new();
    c.update(&out);
    let crc = c.finalize();
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

/// Generation-tagged rows for torn-read detection: key_i → "g<g>|key_i|<pad>".
pub const GEN_KEYS: usize = 2000;
pub fn gen_pad(g: usize) -> String {
    std::iter::repeat((b'a' + g as u8) as char).take(8 + g * 5).collect()
}
pub fn gen_blob(g: usize) -> Vec<u8> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..GEN_KEYS)
        .map(|i| (format!("key_{}", i).into_bytes(), format!("g{}|key_{}|{}", g, i, gen_pad(g)).into_bytes()))
        .collect();
    build(&rows)
}
pub fn check_gen_value(key: &str, v: &[u8]) -> Result<(), String> {
    let s = std::str::from_utf8(v).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = s.splitn(3, '|').collect();
    if parts.len() != 3 || !parts[0].starts_with('g') || parts[1] != key {
        return Err(format!("torn/foreign value for {}: {:?}", key, s));
    }
    let g: usize = parts[0][1..].parse().map_err(|_| format!("bad gen {:?}", s))?;
    if parts[2] != gen_pad(g) {
        return Err(format!("torn pad for {}: {:?}", key, s));
    }
    Ok(())
}

pub fn count_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}
pub fn count_maps(needle: &str) -> usize {
    std::fs::read_to_string("/proc/self/maps").map(|s| s.matches(needle).count()).unwrap_or(0)
}
