#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::sha256d::Sha256d80Shani;
use crate::sha256d::{library_sha256d80, Sha256d80, Sha256d80Compression, TargetWords};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const FULL_RANGE_CHUNK: u64 = 1_048_576;
pub const DEFAULT_BATCH_SIZE: u64 = 262_144;

#[derive(Clone, Copy, Debug)]
pub enum Backend {
    Library,
    Specialized80,
    Compression80,
    Shani80,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Library => "library sha2 SHA256d",
            Self::Specialized80 => "specialized scalar SHA256d80",
            Self::Compression80 => "specialized compression SHA256d80",
            Self::Shani80 => "custom x86 SHA-NI SHA256d80",
        }
    }
}

#[derive(Debug)]
pub struct BenchResult {
    pub backend: Backend,
    pub total_hashes: u64,
    pub hashes_per_second: f64,
    pub per_thread_hashes_per_second: f64,
    pub checksum: u64,
}

#[derive(Debug)]
pub struct ScanBenchResult {
    pub total_hashes: u64,
    pub hashes_per_second: f64,
    pub per_thread_hashes_per_second: f64,
    pub matches: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interleave {
    One,
    Two,
    Four,
    Eight,
}

impl Interleave {
    pub fn from_width(width: usize) -> Result<Self, String> {
        match width {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            4 => Ok(Self::Four),
            8 => Ok(Self::Eight),
            _ => Err(format!(
                "unsupported interleave width {width}; supported values are 1, 2, 4, and 8"
            )),
        }
    }

    pub fn width(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WorkDesign {
    SplitNonce,
    PerWorkerExtraNonce,
}

impl WorkDesign {
    pub fn name(self) -> &'static str {
        match self {
            Self::SplitNonce => "shared header, split nonce ranges",
            Self::PerWorkerExtraNonce => "per-worker extraNonce/header contexts",
        }
    }
}

pub fn run(backend: Backend, header: [u8; 80], duration: Duration, threads: usize) -> BenchResult {
    run_with_batch_size(backend, header, duration, threads, DEFAULT_BATCH_SIZE)
}

pub fn run_with_batch_size(
    backend: Backend,
    header: [u8; 80],
    duration: Duration,
    threads: usize,
    batch_size: u64,
) -> BenchResult {
    let next_nonce = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + duration;
    let started = Instant::now();
    let mut handles = Vec::with_capacity(threads);

    for _ in 0..threads {
        let next_nonce = Arc::clone(&next_nonce);
        handles.push(thread::spawn(move || {
            let mut local_count = 0u64;
            let mut checksum = 0u64;
            let specialized = Sha256d80::new(&header);
            let compression = Sha256d80Compression::new(&header);
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let shani = Sha256d80Shani::new(&header);

            while Instant::now() < deadline {
                let start = next_nonce.fetch_add(batch_size, Ordering::Relaxed);
                match backend {
                    Backend::Library => {
                        let (count, sum) = run_library_batch(header, start, batch_size);
                        local_count += count;
                        checksum ^= sum.rotate_left((count & 63) as u32);
                    }
                    Backend::Specialized80 => {
                        let (count, sum) = run_specialized_batch(&specialized, start, batch_size);
                        local_count += count;
                        checksum ^= sum.rotate_left((count & 63) as u32);
                    }
                    Backend::Compression80 => {
                        let (count, sum) = run_compression_batch(&compression, start, batch_size);
                        local_count += count;
                        checksum ^= sum.rotate_left((count & 63) as u32);
                    }
                    Backend::Shani80 => {
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        {
                            let shani = shani.as_ref().expect("SHA-NI backend is not available");
                            let (count, sum) = run_shani_batch(shani, start, batch_size);
                            local_count += count;
                            checksum ^= sum.rotate_left((count & 63) as u32);
                        }
                        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                        unreachable!("SHA-NI backend is only available on x86/x86_64");
                    }
                }
            }

            black_box((local_count, checksum))
        }));
    }

    let mut total_hashes = 0u64;
    let mut checksum = 0u64;
    for handle in handles {
        let (count, sum) = handle.join().expect("benchmark worker panicked");
        total_hashes += count;
        checksum ^= sum.rotate_left((count & 63) as u32);
    }

    let elapsed = started.elapsed().as_secs_f64();
    let hashes_per_second = total_hashes as f64 / elapsed;
    BenchResult {
        backend,
        total_hashes,
        hashes_per_second,
        per_thread_hashes_per_second: hashes_per_second / threads as f64,
        checksum,
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn run_work_design(
    design: WorkDesign,
    header: [u8; 80],
    duration: Duration,
    threads: usize,
) -> BenchResult {
    match design {
        WorkDesign::SplitNonce => run_with_batch_size(
            Backend::Shani80,
            header,
            duration,
            threads,
            DEFAULT_BATCH_SIZE,
        ),
        WorkDesign::PerWorkerExtraNonce => run_per_worker_contexts(header, duration, threads),
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn run_target_scan_with_options(
    header: [u8; 80],
    target: [u8; 32],
    duration: Duration,
    threads: usize,
    batch_size: u64,
    pin_threads: bool,
    interleave: Interleave,
) -> ScanBenchResult {
    let target = TargetWords::from_be_bytes(target);
    let next_nonce = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let mut handles = Vec::with_capacity(threads);

    for worker_id in 0..threads {
        let next_nonce = Arc::clone(&next_nonce);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            maybe_pin_current_thread(worker_id, pin_threads);
            let mut local_count = 0u64;
            let mut matches = 0u64;
            let shani = Sha256d80Shani::new(&header).expect("SHA-NI backend is not available");

            while !stop.load(Ordering::Relaxed) {
                let start = next_nonce.fetch_add(batch_size, Ordering::Relaxed);
                matches += match interleave {
                    Interleave::One => shani.count_batch_with_target(start, batch_size, target),
                    Interleave::Two => {
                        shani.count_batch_with_target_interleaved2(start, batch_size, target)
                    }
                    Interleave::Four => {
                        shani.count_batch_with_target_interleaved4(start, batch_size, target)
                    }
                    Interleave::Eight => {
                        shani.count_batch_with_target_interleaved8(start, batch_size, target)
                    }
                };
                local_count += batch_size;
            }

            black_box((local_count, matches))
        }));
    }

    thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);

    let mut total_hashes = 0u64;
    let mut matches = 0u64;
    for handle in handles {
        let (count, found) = handle.join().expect("target scan worker panicked");
        total_hashes += count;
        matches += found;
    }

    let elapsed = started.elapsed().as_secs_f64();
    let hashes_per_second = total_hashes as f64 / elapsed;
    ScanBenchResult {
        total_hashes,
        hashes_per_second,
        per_thread_hashes_per_second: hashes_per_second / threads as f64,
        matches,
    }
}

fn maybe_pin_current_thread(worker_id: usize, pin_threads: bool) {
    if !pin_threads {
        return;
    }
    pin_current_thread(worker_id);
}

#[cfg(target_os = "linux")]
fn pin_current_thread(worker_id: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(worker_id, &mut set);
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if rc != 0 {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("warning: failed to pin worker {worker_id} to CPU {worker_id}\n")
                    .as_bytes(),
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(_worker_id: usize) {}

fn run_library_batch(mut header: [u8; 80], start: u64, count: u64) -> (u64, u64) {
    let mut checksum = 0u64;
    for offset in 0..count {
        let nonce = start.wrapping_add(offset) as u32;
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let digest = library_sha256d80(&header);
        let head = u64::from_be_bytes(digest[0..8].try_into().expect("digest length"));
        let tail = u64::from_be_bytes(digest[24..32].try_into().expect("digest length"));
        checksum ^= head ^ tail.rotate_left(nonce & 63);
    }
    black_box((count, checksum))
}

fn run_specialized_batch(specialized: &Sha256d80, start: u64, count: u64) -> (u64, u64) {
    let mut checksum = 0u64;
    for offset in 0..count {
        let nonce = start.wrapping_add(offset) as u32;
        let digest = specialized.hash_nonce_words(nonce);
        checksum ^= digest.checksum().rotate_left(nonce & 63);
    }
    black_box((count, checksum))
}

fn run_compression_batch(compression: &Sha256d80Compression, start: u64, count: u64) -> (u64, u64) {
    let mut checksum = 0u64;
    for offset in 0..count {
        let nonce = start.wrapping_add(offset) as u32;
        let digest = compression.hash_nonce_words(nonce);
        checksum ^= digest.checksum().rotate_left(nonce & 63);
    }
    black_box((count, checksum))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn run_shani_batch(shani: &Sha256d80Shani, start: u64, count: u64) -> (u64, u64) {
    black_box(shani.checksum_batch(start, count))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn run_per_worker_contexts(header: [u8; 80], duration: Duration, threads: usize) -> BenchResult {
    let deadline = Instant::now() + duration;
    let started = Instant::now();
    let mut handles = Vec::with_capacity(threads);

    for worker_id in 0..threads {
        handles.push(thread::spawn(move || {
            let mut local_count = 0u64;
            let mut checksum = 0u64;
            let mut extra_nonce = worker_id as u64;

            while Instant::now() < deadline {
                let worker_header = header_for_extra_nonce(header, extra_nonce);
                let shani =
                    Sha256d80Shani::new(&worker_header).expect("SHA-NI backend is not available");
                let mut nonce_start = 0u64;

                while nonce_start <= u32::MAX as u64 && Instant::now() < deadline {
                    let remaining = u32::MAX as u64 + 1 - nonce_start;
                    let count = remaining.min(FULL_RANGE_CHUNK);
                    let (hashed, sum) = shani.checksum_batch(nonce_start, count);
                    local_count += hashed;
                    checksum ^= sum.rotate_left((hashed & 63) as u32);
                    nonce_start += hashed;
                }

                extra_nonce = extra_nonce.wrapping_add(threads as u64);
            }

            black_box((local_count, checksum))
        }));
    }

    let mut total_hashes = 0u64;
    let mut checksum = 0u64;
    for handle in handles {
        let (count, sum) = handle.join().expect("benchmark worker panicked");
        total_hashes += count;
        checksum ^= sum.rotate_left((count & 63) as u32);
    }

    let elapsed = started.elapsed().as_secs_f64();
    let hashes_per_second = total_hashes as f64 / elapsed;
    BenchResult {
        backend: Backend::Shani80,
        total_hashes,
        hashes_per_second,
        per_thread_hashes_per_second: hashes_per_second / threads as f64,
        checksum,
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn header_for_extra_nonce(mut header: [u8; 80], extra_nonce: u64) -> [u8; 80] {
    // Simulate extraNonce changing the coinbase -> merkle root -> header midstate.
    // This keeps benchmark setup cheap while forcing a distinct SHA-NI context per worker.
    let mut x = extra_nonce.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for byte in &mut header[36..68] {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *byte ^= (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8;
    }
    header[76..80].copy_from_slice(&0u32.to_le_bytes());
    header
}
