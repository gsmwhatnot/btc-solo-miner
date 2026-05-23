use crate::benchmark::{self, Interleave};
use crate::config::{Config, CpuFeatures, OptimizedSettings};
use crate::sha256d::decode_hex_80;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const INIT_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
const DEFAULT_INIT_BATCH_SIZES: [u64; 3] = [65_536, 262_144, 1_048_576];
const DEFAULT_INIT_INTERLEAVES: [Interleave; 4] = [
    Interleave::One,
    Interleave::Two,
    Interleave::Four,
    Interleave::Eight,
];

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn run_init(
    config_path: &Path,
    mut config: Config,
    benchmark_seconds: u64,
) -> Result<(), String> {
    use crate::config::save_config;
    use crate::sha256d::shani_available;

    if !shani_available() {
        return Err("custom SHA-NI backend is not available on this CPU".to_string());
    }

    let header = decode_hex_80(INIT_HEADER_HEX)?;
    let target = [0xff; 32];
    let duration = Duration::from_secs(benchmark_seconds);
    let thread_candidates = thread_candidates(config.reserved_threads);
    let mut best: Option<OptimizedSettings> = None;
    let mut candidates_tested = 0usize;

    println!("Machine init benchmark");
    println!("Config path: {}", config_path.display());
    println!("Sample duration per candidate: {benchmark_seconds}s");
    println!("CPU features: {}", CpuFeatures::detect().summary());
    println!("Thread candidates: {:?}", thread_candidates);
    println!("Batch candidates: {:?}", DEFAULT_INIT_BATCH_SIZES);
    println!("Interleave candidates: 1, 2, 4, 8");
    println!();

    for threads in thread_candidates {
        for batch_size in DEFAULT_INIT_BATCH_SIZES {
            for interleave in DEFAULT_INIT_INTERLEAVES {
                candidates_tested += 1;
                let result = benchmark::run_target_scan_with_options(
                    header, target, duration, threads, batch_size, false, interleave,
                );
                println!(
                    "candidate threads={} batch={} interleave={} -> {}",
                    threads,
                    batch_size,
                    interleave.width(),
                    format_hps(result.hashes_per_second)
                );

                if best
                    .as_ref()
                    .map(|current| result.hashes_per_second > current.hashes_per_second)
                    .unwrap_or(true)
                {
                    best = Some(OptimizedSettings {
                        threads,
                        batch_size,
                        interleave: interleave.width(),
                        pin_threads: false,
                        hashes_per_second: result.hashes_per_second,
                        per_thread_hashes_per_second: result.per_thread_hashes_per_second,
                        cpu_features: CpuFeatures::detect(),
                        benchmarked_at_unix: unix_now(),
                    });
                }
            }
        }
    }

    let settings = best.ok_or_else(|| "init benchmark did not test any candidates".to_string())?;
    config.initialized = true;
    config.optimized = Some(settings.clone());
    save_config(config_path, &config)?;

    println!();
    println!("Init complete");
    println!("Best threads: {}", settings.threads);
    println!("Best batch size: {}", settings.batch_size);
    println!("Best interleave: {}", settings.interleave);
    println!("Best hash rate: {}", format_hps(settings.hashes_per_second));
    println!(
        "Per thread: {}",
        format_hps(settings.per_thread_hashes_per_second)
    );
    println!("CPU features: {}", settings.cpu_features.summary());
    println!("Wrote optimized settings to {}", config_path.display());

    println!("Candidates tested: {candidates_tested}");
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn run_init(
    _config_path: &Path,
    _config: Config,
    _benchmark_seconds: u64,
) -> Result<(), String> {
    Err("--init currently requires x86/x86_64 SHA-NI".to_string())
}

fn thread_candidates(reserved_threads: usize) -> Vec<usize> {
    let available = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let preferred = available.saturating_sub(reserved_threads).max(1);
    let half = (preferred / 2).max(1);
    let mut values = vec![half, preferred, available];
    values.sort_unstable();
    values.dedup();
    values
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn format_hps(value: f64) -> String {
    const UNITS: [(&str, f64); 7] = [
        ("EH/s", 1e18),
        ("PH/s", 1e15),
        ("TH/s", 1e12),
        ("GH/s", 1e9),
        ("MH/s", 1e6),
        ("KH/s", 1e3),
        ("H/s", 1.0),
    ];

    for (unit, scale) in UNITS {
        if value >= scale {
            return format!("{:.3} {unit}", value / scale);
        }
    }
    format!("{value:.3} H/s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_candidates_reserve_headroom() {
        let values = thread_candidates(1);
        assert!(!values.is_empty());
        assert!(values.iter().all(|value| *value > 0));
    }
}
