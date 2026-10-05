// engine.rs -- orchestration: candidate producer + N verifier threads,
// checkpoint/resume sessions, live stats, benchmark mode. Port of Engine.cs.
// (M3: producer/consumer + checkpoint. M2: Benchmark only.)
use crate::verifier::Verifier;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Measures real verification throughput (candidates/second) of a verifier
/// over the given thread count; threads == 0 means auto (cores - 2, capped at
/// 32). Each thread hammers pseudo-random passwords until the deadline and
/// results are summed. Port of Benchmark.Measure.
pub fn bench_measure(
    verifier: &Arc<dyn Verifier + Send + Sync>,
    threads: u32,
    seconds: u32,
) -> f64 {
    let threads = if threads == 0 {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as i64;
        (cores - 2).clamp(1, 32) as u32
    } else {
        threads
    };
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Duration::from_secs(seconds as u64);
    let start = Instant::now();
    let mut handles = Vec::new();
    for t in 0..threads {
        let v = verifier.clone();
        let total = total.clone();
        handles.push(std::thread::spawn(move || {
            let mut mine: u64 = 0;
            let mut seed: u64 = (t as u64).wrapping_mul(7919).wrapping_add(13);
            while start.elapsed() < deadline {
                // cheap xorshift PRNG -> base64-ish password, no allocation churn
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pwd = format!("{:016x}", seed);
                let _ = v.verify(&pwd);
                mine += 1;
            }
            total.fetch_add(mine, Ordering::Relaxed);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed().as_secs_f64();
    total.load(Ordering::Relaxed) as f64 / elapsed
}

