mod benchmark;
mod config;
mod init;
mod mine;
mod real_block;
mod rpc;
mod sha256d;

use benchmark::{
    Backend, BenchResult, Interleave, ScanBenchResult, WorkDesign, DEFAULT_BATCH_SIZE,
};
use config::{load_config, load_or_default};
use mine::MiningOverrides;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use sha256d::{avx512_available, avx512_sha256d80, shani_available, shani_sha256d80};
use sha256d::{compression_sha256d80, decode_hex_80, library_sha256d80, specialized_sha256d80};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_BENCH_SECONDS: u64 = 60;
const DEFAULT_INIT_BENCH_SECONDS: u64 = 15;
const DEFAULT_CONFIG_PATH: &str = "config.json";
const BENCH_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

#[derive(Debug)]
struct Args {
    init: bool,
    mine: bool,
    benchmark: bool,
    scan_benchmark: bool,
    work_design_benchmark: bool,
    real_block_benchmark: bool,
    benchmark_seconds: u64,
    benchmark_seconds_set: bool,
    threads: Option<usize>,
    config_path: PathBuf,
    nonce_window: u64,
    confirmations: u64,
    batch_size: Option<u64>,
    pin_threads: bool,
    interleave: Option<Interleave>,
    help: bool,
}

fn main() {
    if let Err(err) = run_cli() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<(), String> {
    let args = parse_args(env::args().skip(1))?;
    if args.help {
        print_help();
        return Ok(());
    }

    if args.init {
        let config = load_or_default(&args.config_path)?;
        let seconds = if args.benchmark_seconds_set {
            args.benchmark_seconds
        } else {
            DEFAULT_INIT_BENCH_SECONDS
        };
        init::run_init(&args.config_path, config, seconds)?;
        Ok(())
    } else if args.mine {
        let config = load_config(&args.config_path)?;
        mine::run(
            config,
            MiningOverrides {
                threads: args.threads,
                batch_size: args.batch_size,
                interleave: args.interleave,
                pin_threads: args.pin_threads.then_some(true),
            },
        )
    } else if args.scan_benchmark {
        run_scan_benchmark(
            args.benchmark_seconds,
            args.threads.unwrap_or_else(default_threads),
            args.batch_size.unwrap_or(DEFAULT_BATCH_SIZE),
            args.pin_threads,
            args.interleave.unwrap_or(Interleave::One),
        )
    } else if args.work_design_benchmark {
        run_work_design_benchmark(
            args.benchmark_seconds,
            args.threads.unwrap_or_else(default_threads),
        )
    } else if args.real_block_benchmark {
        run_real_block_benchmark(
            args.threads.unwrap_or_else(default_threads),
            args.nonce_window,
            args.confirmations,
            args.interleave.unwrap_or(Interleave::One),
        )
    } else if args.benchmark {
        run_benchmark(
            args.benchmark_seconds,
            args.threads.unwrap_or_else(default_threads),
        )
    } else {
        let config = load_or_default(&args.config_path)?;
        print_config_status(&args.config_path, &config);
        Ok(())
    }
}

fn parse_args<I>(mut input: I) -> Result<Args, String>
where
    I: Iterator<Item = String>,
{
    let mut init = false;
    let mut mine = false;
    let mut benchmark = false;
    let mut scan_benchmark = false;
    let mut work_design_benchmark = false;
    let mut real_block_benchmark = false;
    let mut benchmark_seconds = DEFAULT_BENCH_SECONDS;
    let mut benchmark_seconds_set = false;
    let mut threads = None;
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut nonce_window = 5_000_000;
    let mut confirmations = 6;
    let mut batch_size = None;
    let mut pin_threads = false;
    let mut interleave = None;
    let mut help = false;

    while let Some(arg) = input.next() {
        match arg.as_str() {
            "--init" => init = true,
            "--mine" => mine = true,
            "--benchmark" => benchmark = true,
            "--scan-benchmark" => scan_benchmark = true,
            "--work-design-benchmark" => work_design_benchmark = true,
            "--real-block-benchmark" => real_block_benchmark = true,
            "--help" | "-h" => help = true,
            "--benchmark-seconds" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--benchmark-seconds requires a value".to_string())?;
                benchmark_seconds = parse_positive_u64("--benchmark-seconds", &value)?;
                benchmark_seconds_set = true;
            }
            "--threads" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--threads requires a value".to_string())?;
                threads = Some(parse_positive_usize("--threads", &value)?);
            }
            "--config" => {
                config_path = PathBuf::from(
                    input
                        .next()
                        .ok_or_else(|| "--config requires a path".to_string())?,
                );
            }
            "--nonce-window" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--nonce-window requires a value".to_string())?;
                nonce_window = parse_positive_u64("--nonce-window", &value)?;
            }
            "--confirmations" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--confirmations requires a value".to_string())?;
                confirmations = parse_positive_u64("--confirmations", &value)?;
            }
            "--batch-size" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--batch-size requires a value".to_string())?;
                batch_size = Some(parse_positive_u64("--batch-size", &value)?);
            }
            "--pin-threads" => pin_threads = true,
            "--interleave" => {
                let value = input
                    .next()
                    .ok_or_else(|| "--interleave requires a value".to_string())?;
                interleave = Some(Interleave::from_width(parse_positive_usize(
                    "--interleave",
                    &value,
                )?)?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Args {
        init,
        mine,
        benchmark,
        scan_benchmark,
        work_design_benchmark,
        real_block_benchmark,
        benchmark_seconds,
        benchmark_seconds_set,
        threads,
        config_path,
        nonce_window,
        confirmations,
        batch_size,
        pin_threads,
        interleave,
        help,
    })
}

fn run_benchmark(seconds: u64, threads: usize) -> Result<(), String> {
    let header = decode_hex_80(BENCH_HEADER_HEX)?;
    let library = library_sha256d80(&header);
    let specialized = specialized_sha256d80(&header);
    let compression = compression_sha256d80(&header);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let avx512 = avx512_sha256d80(&header);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let shani = shani_sha256d80(&header);
    if library != specialized || library != compression {
        return Err("candidate SHA256d80 output does not match library output".to_string());
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(avx512) = avx512 {
        if library != avx512 {
            return Err("custom AVX512 SHA256d80 output does not match library output".to_string());
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(shani) = shani {
        if library != shani {
            return Err("custom SHA-NI SHA256d80 output does not match library output".to_string());
        }
    }

    println!("Solo Miner SHA256d benchmark");
    println!("Threads: {threads}");
    println!("Duration per backend: {seconds}s");
    println!("CPU features: {}", cpu_features());
    println!("Fixed header: Bitcoin genesis block header");
    println!();

    let duration = Duration::from_secs(seconds);
    let baseline = benchmark::run(Backend::Library, header, duration, threads);
    print_result(&baseline);

    let candidate = benchmark::run(Backend::Specialized80, header, duration, threads);
    print_result(&candidate);

    let compression_candidate = benchmark::run(Backend::Compression80, header, duration, threads);
    print_result(&compression_candidate);

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let avx512_candidate = if avx512_available() {
        let result = benchmark::run(Backend::Avx512, header, duration, threads);
        print_result(&result);
        Some(result)
    } else {
        println!("Backend: custom x86 AVX512 SHA256d80");
        println!("  skipped: required AVX512F CPU features are not available");
        println!();
        None
    };

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let shani_candidate = if shani_available() {
        let result = benchmark::run(Backend::Shani80, header, duration, threads);
        print_result(&result);
        Some(result)
    } else {
        println!("Backend: custom x86 SHA-NI SHA256d80");
        println!("  skipped: required SHA-NI CPU features are not available");
        println!();
        None
    };

    println!(
        "Scalar speedup: {:.3}x",
        candidate.hashes_per_second / baseline.hashes_per_second
    );
    println!(
        "Compression speedup: {:.3}x",
        compression_candidate.hashes_per_second / baseline.hashes_per_second
    );
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(result) = &avx512_candidate {
        println!(
            "Custom AVX512 speedup: {:.3}x",
            result.hashes_per_second / baseline.hashes_per_second
        );
        println!(
            "Custom AVX512 vs compression: {:.3}x",
            result.hashes_per_second / compression_candidate.hashes_per_second
        );
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(result) = &shani_candidate {
        println!(
            "Custom SHA-NI speedup: {:.3}x",
            result.hashes_per_second / baseline.hashes_per_second
        );
        println!(
            "Custom SHA-NI vs compression: {:.3}x",
            result.hashes_per_second / compression_candidate.hashes_per_second
        );
    }
    println!(
        "Checksums: baseline={:016x} scalar={:016x} compression={:016x}",
        baseline.checksum, candidate.checksum, compression_candidate.checksum
    );
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(result) = &avx512_candidate {
        println!("Custom AVX512 checksum: {:016x}", result.checksum);
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(result) = &shani_candidate {
        println!("Custom SHA-NI checksum: {:016x}", result.checksum);
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn run_scan_benchmark(
    seconds: u64,
    threads: usize,
    batch_size: u64,
    pin_threads: bool,
    interleave: Interleave,
) -> Result<(), String> {
    if !shani_available() {
        return Err("custom SHA-NI backend is not available on this CPU".to_string());
    }

    let header = decode_hex_80(BENCH_HEADER_HEX)?;
    let target = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let result = benchmark::run_target_scan_with_options(
        header,
        target,
        Duration::from_secs(seconds),
        threads,
        batch_size,
        pin_threads,
        interleave,
    );

    println!("Real mining-style target-scan benchmark");
    println!("Threads: {threads}");
    println!("Duration: {seconds}s");
    println!("Batch size: {batch_size}");
    println!("Thread pinning: {}", if pin_threads { "on" } else { "off" });
    println!("Interleave: {} stream(s)", interleave.width());
    println!("CPU features: {}", cpu_features());
    println!("Backend: custom x86 SHA-NI SHA256d80");
    println!("Target: all-ones benchmark target");
    println!();
    print_scan_result(&result);
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn run_scan_benchmark(
    _seconds: u64,
    _threads: usize,
    _batch_size: u64,
    _pin_threads: bool,
    _interleave: Interleave,
) -> Result<(), String> {
    Err("scan benchmark currently requires x86/x86_64 SHA-NI".to_string())
}

fn print_scan_result(result: &ScanBenchResult) {
    println!("Hashes checked: {}", format_u64(result.total_hashes));
    println!("Hashes/sec:     {}", format_hps(result.hashes_per_second));
    println!(
        "Per thread:     {}",
        format_hps(result.per_thread_hashes_per_second)
    );
    println!("Matches:        {}", format_u64(result.matches));
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn run_work_design_benchmark(seconds: u64, threads: usize) -> Result<(), String> {
    if !shani_available() {
        return Err("custom SHA-NI backend is not available on this CPU".to_string());
    }

    let header = decode_hex_80(BENCH_HEADER_HEX)?;
    let duration = Duration::from_secs(seconds);

    println!("CPU work-design benchmark");
    println!("Threads: {threads}");
    println!("Duration per design: {seconds}s");
    println!("CPU features: {}", cpu_features());
    println!("Backend: custom x86 SHA-NI SHA256d80");
    println!();

    let split = benchmark::run_work_design(WorkDesign::SplitNonce, header, duration, threads);
    print_design_result(WorkDesign::SplitNonce, &split);

    let per_worker =
        benchmark::run_work_design(WorkDesign::PerWorkerExtraNonce, header, duration, threads);
    print_design_result(WorkDesign::PerWorkerExtraNonce, &per_worker);

    println!(
        "Per-worker-context vs split-nonce: {:.3}x",
        per_worker.hashes_per_second / split.hashes_per_second
    );
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn run_work_design_benchmark(_seconds: u64, _threads: usize) -> Result<(), String> {
    Err("work-design benchmark currently requires x86/x86_64 SHA-NI".to_string())
}

fn print_design_result(design: WorkDesign, result: &BenchResult) {
    println!("Design: {}", design.name());
    println!("  total hashes: {}", format_u64(result.total_hashes));
    println!("  hashes/sec:   {}", format_hps(result.hashes_per_second));
    println!(
        "  per thread:   {}",
        format_hps(result.per_thread_hashes_per_second)
    );
    println!("  checksum:     {:016x}", result.checksum);
    println!();
}

fn run_real_block_benchmark(
    threads: usize,
    nonce_window: u64,
    confirmations: u64,
    interleave: Interleave,
) -> Result<(), String> {
    let config = real_block::RealBlockScanConfig {
        threads,
        nonce_window,
        confirmations,
        interleave,
    };
    let result = real_block::run(config)?;
    let hps = result.total_hashes as f64 / result.elapsed_seconds;

    println!("Real block SHA-NI scan benchmark");
    println!("Threads: {threads}");
    println!("Interleave: {} stream(s)", interleave.width());
    println!("CPU features: {}", cpu_features());
    println!("Block height: {}", result.block.height);
    println!("Block hash:   {}", result.block.hash);
    println!("Actual nonce: {}", result.actual_nonce);
    println!(
        "Scan range:   {}..={}",
        result.start_nonce, result.end_nonce
    );
    println!("Target:       {}", hex_be(result.target));
    println!();
    println!("Hashes checked: {}", format_u64(result.total_hashes));
    println!("Elapsed:        {:.6}s", result.elapsed_seconds);
    println!("Scan rate:      {}", format_hps(hps));
    match (result.found_nonce, result.found_hash) {
        (Some(nonce), Some(hash)) => {
            println!("Found nonce:    {nonce}");
            println!("Found hash:     {}", display_block_hash(hash));
            if nonce == result.actual_nonce {
                println!("Validation:     matched the historical block nonce");
            } else {
                println!("Validation:     found a valid nonce different from the historical nonce");
            }
        }
        _ => println!("Found nonce:    none in selected range"),
    }
    Ok(())
}

fn print_result(result: &BenchResult) {
    println!("Backend: {}", result.backend.name());
    println!("  total hashes: {}", format_u64(result.total_hashes));
    println!("  hashes/sec:   {}", format_hps(result.hashes_per_second));
    println!(
        "  per thread:   {}",
        format_hps(result.per_thread_hashes_per_second)
    );
    println!("  checksum:     {:016x}", result.checksum);
    println!();
}

fn print_help() {
    println!("Usage:");
    println!("  solo-miner --init [--benchmark-seconds 15] [--config config.json]");
    println!("  solo-miner --mine [--config config.json] [--threads N] [--batch-size N] [--interleave N]");
    println!("  solo-miner --benchmark [--benchmark-seconds 60] [--threads N]");
    println!("  solo-miner --scan-benchmark [--benchmark-seconds 60] [--threads N]");
    println!("  solo-miner --real-block-benchmark [--threads N] [--nonce-window 5000000]");
    println!("  solo-miner [--config config.json]");
    println!();
    println!("Options:");
    println!("  --init                   Tune mining settings and write config.json");
    println!("  --mine                   Start live Bitcoin RPC mining");
    println!("  --benchmark              Run SHA256d benchmark mode");
    println!("  --scan-benchmark         Run mining-style target comparison benchmark");
    println!("  --real-block-benchmark   Fetch a confirmed block and scan around its nonce");
    println!("  --benchmark-seconds N    Seconds per benchmark backend, default 60");
    println!("  --threads N              Worker threads, default detected CPU count");
    println!("  --batch-size N           Nonces per worker claim/check, default 262144");
    println!("  --pin-threads            Pin scan benchmark workers to CPU IDs");
    println!("  --interleave N           SHA-NI streams per worker, supported: 1, 2, 4, or 8");
    println!("  --nonce-window N         Real-block scan range on each side, default 5000000");
    println!("  --confirmations N        Confirmations for fetched block, default 6");
    println!("  --config PATH            Config path, default config.json");
    println!("  --help                   Show this help");
}

fn print_config_status(path: &std::path::Path, config: &config::Config) {
    println!("Config path: {}", path.display());
    println!("Initialized: {}", config.initialized);
    if !config.initialized {
        println!("warning: run solo-miner --init for best hash rate on this machine");
    }
    println!("Wallet address: {}", empty_marker(&config.wallet_address));
    println!("Mining mode: {:?}", config.mining_mode);
    println!("Template poll seconds: {}", config.template_poll_seconds);
    println!("Longpoll: {}", config.longpoll);
    println!("Show progress: {}", config.show_progress);
    println!("Reserved threads: {}", config.reserved_threads);
    println!("RPC servers: {}", config.rpc_servers.len());
    for server in &config.rpc_servers {
        println!(
            "  {} {} username={} password={}",
            server.name,
            server.url,
            empty_marker(&server.username),
            mask_secret(&server.password)
        );
    }
    if let Some(settings) = &config.optimized {
        println!("Optimized threads: {}", settings.threads);
        println!("Optimized batch size: {}", settings.batch_size);
        println!("Optimized interleave: {}", settings.interleave);
        println!("Optimized pin threads: {}", settings.pin_threads);
        println!(
            "Optimized hash rate: {}",
            format_hps(settings.hashes_per_second)
        );
        println!("CPU features: {}", settings.cpu_features.summary());
    } else {
        println!("Optimized settings: none");
    }
    println!("Use --mine to start live mining.");
}

fn empty_marker(value: &str) -> String {
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        value.to_string()
    }
}

fn parse_positive_u64(name: &str, value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if parsed == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(parsed)
    }
}

fn parse_positive_usize(name: &str, value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if parsed == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(parsed)
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        "<empty>".to_string()
    } else {
        "********".to_string()
    }
}

fn format_u64(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::with_capacity(text.len() + text.len() / 3);
    for (i, ch) in text.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
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

fn hex_be(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_block_hash(internal_hash: [u8; 32]) -> String {
    internal_hash
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn cpu_features() -> String {
    let mut features = Vec::new();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        features.push(format!("sha_ni={}", std::is_x86_feature_detected!("sha")));
        features.push(format!("avx2={}", std::is_x86_feature_detected!("avx2")));
        features.push(format!(
            "avx512f={}",
            std::is_x86_feature_detected!("avx512f")
        ));
        features.push(format!(
            "avx512vl={}",
            std::is_x86_feature_detected!("avx512vl")
        ));
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        features.push("x86 feature detection unavailable".to_string());
    }

    features.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_benchmark_args() {
        let args = parse_args(
            [
                "--benchmark",
                "--benchmark-seconds",
                "2",
                "--threads",
                "4",
                "--config",
                "mine.json",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();

        assert!(args.benchmark);
        assert_eq!(args.benchmark_seconds, 2);
        assert_eq!(args.threads, Some(4));
        assert_eq!(args.config_path, PathBuf::from("mine.json"));
    }

    #[test]
    fn rejects_zero_threads() {
        assert!(parse_args(["--threads", "0"].into_iter().map(String::from)).is_err());
    }
}
