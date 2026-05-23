use crate::benchmark::Interleave;
use crate::sha256d::{
    bits_to_target, decode_hex_80, hash_meets_target, library_sha256d80, shani_available,
    Sha256d80Shani, TargetWords,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

const API_BASE: &str = "https://mempool.space/api";
const BATCH_SIZE: u64 = 65_536;

#[derive(Clone, Debug)]
pub struct BlockHeaderData {
    pub height: u64,
    pub hash: String,
    pub header: [u8; 80],
}

#[derive(Clone, Copy, Debug)]
pub struct RealBlockScanConfig {
    pub threads: usize,
    pub nonce_window: u64,
    pub confirmations: u64,
    pub interleave: Interleave,
}

#[derive(Debug)]
pub struct RealBlockScanResult {
    pub block: BlockHeaderData,
    pub actual_nonce: u32,
    pub start_nonce: u32,
    pub end_nonce: u32,
    pub target: [u8; 32],
    pub total_hashes: u64,
    pub elapsed_seconds: f64,
    pub found_nonce: Option<u32>,
    pub found_hash: Option<[u8; 32]>,
}

pub fn run(config: RealBlockScanConfig) -> Result<RealBlockScanResult, String> {
    if !shani_available() {
        return Err("custom SHA-NI backend is not available on this CPU".to_string());
    }

    let block = fetch_confirmed_block_header(config.confirmations)?;
    let actual_nonce = u32::from_le_bytes(block.header[76..80].try_into().expect("nonce length"));
    let target = bits_to_target(block.header[72..76].try_into().expect("bits length"))?;
    let target_words = TargetWords::from_be_bytes(target);
    let actual_hash = library_sha256d80(&block.header);
    if !hash_meets_target(actual_hash, target) {
        return Err("fetched block header does not meet its encoded target".to_string());
    }

    let (start_nonce, end_nonce) = nonce_range_around(actual_nonce, config.nonce_window);
    let range_len = end_nonce as u64 - start_nonce as u64 + 1;
    let next_offset = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None::<(u32, [u8; 32])>));
    let checked = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    let mut handles = Vec::with_capacity(config.threads);
    for _ in 0..config.threads {
        let next_offset = Arc::clone(&next_offset);
        let found = Arc::clone(&found);
        let result = Arc::clone(&result);
        let checked = Arc::clone(&checked);
        let header = block.header;

        handles.push(thread::spawn(move || {
            let shani = Sha256d80Shani::new(&header).expect("SHA-NI checked before spawning");

            while !found.load(Ordering::Relaxed) {
                let offset = next_offset.fetch_add(BATCH_SIZE, Ordering::Relaxed);
                if offset >= range_len {
                    break;
                }

                let remaining = range_len - offset;
                let count = remaining.min(BATCH_SIZE);
                let start = start_nonce as u64 + offset;
                let batch = match config.interleave {
                    Interleave::One => shani.scan_batch(start, count, target_words),
                    Interleave::Two => shani.scan_batch_interleaved2(start, count, target_words),
                    Interleave::Four => shani.scan_batch_interleaved4(start, count, target_words),
                    Interleave::Eight => shani.scan_batch_interleaved8(start, count, target_words),
                };
                checked.fetch_add(batch.hashes_checked, Ordering::Relaxed);

                if let (Some(nonce), Some(hash)) = (batch.found_nonce, batch.found_hash) {
                    if !found.swap(true, Ordering::Relaxed) {
                        *result.lock().expect("result mutex poisoned") = Some((nonce, hash));
                    }
                    break;
                }
            }
        }));
    }

    for handle in handles {
        handle
            .join()
            .map_err(|_| "scan worker panicked".to_string())?;
    }

    let elapsed_seconds = started.elapsed().as_secs_f64();
    let found_pair = *result.lock().expect("result mutex poisoned");

    Ok(RealBlockScanResult {
        block,
        actual_nonce,
        start_nonce,
        end_nonce,
        target,
        total_hashes: checked.load(Ordering::Relaxed),
        elapsed_seconds,
        found_nonce: found_pair.map(|(nonce, _)| nonce),
        found_hash: found_pair.map(|(_, hash)| hash),
    })
}

fn fetch_confirmed_block_header(confirmations: u64) -> Result<BlockHeaderData, String> {
    let tip_height = http_get_text(&format!("{API_BASE}/blocks/tip/height"))?
        .trim()
        .parse::<u64>()
        .map_err(|err| format!("failed to parse tip height: {err}"))?;
    let confirmations = confirmations.max(1);
    let height = tip_height
        .checked_sub(confirmations - 1)
        .ok_or_else(|| "tip height is lower than requested confirmations".to_string())?;
    let hash = http_get_text(&format!("{API_BASE}/block-height/{height}"))?
        .trim()
        .to_string();
    let header_hex = http_get_text(&format!("{API_BASE}/block/{hash}/header"))?;
    let header = decode_hex_80(header_hex.trim())?;

    Ok(BlockHeaderData {
        height,
        hash,
        header,
    })
}

fn http_get_text(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|err| format!("GET {url} failed: {err}"))?
        .into_string()
        .map_err(|err| format!("failed reading response from {url}: {err}"))
}

fn nonce_range_around(nonce: u32, window: u64) -> (u32, u32) {
    let start = (nonce as u64).saturating_sub(window).min(u32::MAX as u64);
    let end = (nonce as u64).saturating_add(window).min(u32::MAX as u64);
    (start as u32, end as u32)
}
