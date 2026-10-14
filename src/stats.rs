//! Lock-free log-linear latency histogram (8 sub-buckets per power of two,
//! ≤ 12.5 % relative error). Only sampled lookups (1 in 256) record into it.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const BUCKETS: usize = 64 * 8;

pub(crate) struct LatencyHistogram {
    counts: Box<[AtomicU64]>,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self { counts: (0..BUCKETS).map(|_| AtomicU64::new(0)).collect() }
    }
}

fn index(ns: u64) -> usize {
    if ns < 8 {
        return ns as usize;
    }
    let e = 63 - ns.leading_zeros() as usize;
    let sub = ((ns >> (e - 3)) & 7) as usize;
    ((e - 2) * 8 + sub).min(BUCKETS - 1)
}

fn upper(i: usize) -> u64 {
    if i < 8 {
        return i as u64;
    }
    let e = i / 8 + 2;
    let sub = (i % 8) as u64;
    ((8 + sub + 1) << (e - 3)) - 1
}

/// Percentiles of sampled lookup latencies over a window (nanoseconds).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LatencySnapshot {
    pub samples: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
}

impl LatencyHistogram {
    #[inline]
    pub(crate) fn record(&self, d: Duration) {
        let ns = d.as_nanos().min(u64::MAX as u128) as u64;
        self.counts[index(ns)].fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically take and reset the histogram.
    pub(crate) fn drain(&self) -> LatencySnapshot {
        let c: Vec<u64> = self.counts.iter().map(|a| a.swap(0, Ordering::Relaxed)).collect();
        let total: u64 = c.iter().sum();
        let mut s = LatencySnapshot { samples: total, ..Default::default() };
        if total == 0 {
            return s;
        }
        let q = |p: f64| {
            let rank = ((p * total as f64) + 0.5).max(1.0) as u64;
            let mut acc = 0;
            for (i, n) in c.iter().enumerate() {
                acc += n;
                if acc >= rank {
                    return upper(i);
                }
            }
            upper(BUCKETS - 1)
        };
        s.p50 = q(0.50);
        s.p95 = q(0.95);
        s.p99 = q(0.99);
        s.max = c.iter().rposition(|&n| n > 0).map(upper).unwrap_or(0);
        s
    }

    /// Merge another histogram's counts into this one (used when a map is retired).
    pub(crate) fn absorb(&self, other: &LatencyHistogram) {
        for (a, b) in self.counts.iter().zip(other.counts.iter()) {
            let v = b.swap(0, Ordering::Relaxed);
            if v > 0 {
                a.fetch_add(v, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn buckets_bound_values() {
        for ns in [0u64, 1, 7, 8, 9, 15, 16, 100, 999, 1000, 123_456, 10_000_000] {
            let i = index(ns);
            assert!(upper(i) >= ns, "ns={} i={} upper={}", ns, i, upper(i));
            if i > 0 {
                assert!(upper(i - 1) < ns, "ns={} lower bucket too high", ns);
            }
        }
        let h = LatencyHistogram::default();
        for ns in 1..=100u64 {
            h.record(Duration::from_nanos(ns * 10));
        }
        let s = h.drain();
        assert_eq!(s.samples, 100);
        assert!(s.p50 >= 500 && s.p50 <= 575, "{:?}", s);
        assert!(s.p99 >= 990 && s.p99 <= 1151, "{:?}", s);
        assert_eq!(h.drain().samples, 0);
    }
}
