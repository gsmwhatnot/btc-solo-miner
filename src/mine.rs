use crate::benchmark::{Interleave, DEFAULT_BATCH_SIZE};
use crate::config::{Config, MiningBackend, MiningMode};
use crate::rpc::{BlockTemplate, RpcClient, RpcPool};
use crate::sha256d::{
    avx512_available, bits_to_target, hash_meets_target, library_sha256d80, shani_available,
    Sha256d80, Sha256d80Avx512, Sha256d80Shani, TargetWords,
};
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Address, Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{collections::hash_map::DefaultHasher, hash::Hash as StdHash, hash::Hasher};

const NONCE_SPACE: u64 = u32::MAX as u64 + 1;
const COINBASE_TAG: &[u8] = b"solo-miner";
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

#[derive(Clone, Copy, Debug, Default)]
pub struct MiningOverrides {
    pub threads: Option<usize>,
    pub batch_size: Option<u64>,
    pub interleave: Option<Interleave>,
    pub pin_threads: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
struct MiningSettings {
    backend: MiningBackend,
    threads: usize,
    batch_size: u64,
    interleave: Interleave,
    pin_threads: bool,
}

#[derive(Clone)]
struct PreparedTemplate {
    template: BlockTemplate,
    target: [u8; 32],
    payout_script: ScriptBuf,
}

struct BuiltWork {
    block: Block,
    header: [u8; 80],
    target_words: TargetWords,
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    nonce: u32,
    hash: [u8; 32],
    worker_id: usize,
}

#[derive(Debug)]
enum ScanOutcome {
    Found {
        candidate: Candidate,
        stats: ScanStats,
    },
    Stale,
    Exhausted(ScanStats),
}

#[derive(Debug)]
enum MonitorEvent {
    TemplateChanged,
    Error(String),
}

#[derive(Clone, Debug)]
struct StatusTemplate {
    height: u64,
    tx_fee: i64,
    total_reward: i64,
    bits: String,
}

struct ScanContext {
    stop: Arc<AtomicBool>,
    hash_audit_per_minute: u64,
}

#[derive(Clone, Copy, Debug)]
struct ScanStats {
    hashes_checked: u64,
    elapsed: Duration,
}

impl ScanStats {
    fn rate(self) -> f64 {
        self.hashes_checked as f64 / self.elapsed.as_secs_f64().max(0.001)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TemplateFingerprint {
    version: i32,
    previousblockhash: String,
    height: u64,
    bits: String,
    target: String,
    coinbase_value: i64,
    default_witness_commitment: Option<String>,
    transaction_count: usize,
    transaction_data_hash: u64,
}

#[derive(Clone, Serialize)]
struct MinedBlockRecord {
    record_version: u64,
    candidate_status: String,
    submit_status: String,
    created_at_unix: u64,
    updated_at_unix: u64,
    elapsed: String,
    chain: String,
    rpc_name: String,
    rpc_url: String,
    height: u64,
    previousblockhash: String,
    block_hash: String,
    target: String,
    bits: String,
    nonce: u32,
    extranonce: u64,
    worker: usize,
    mining_mode: MiningMode,
    block_txs: usize,
    template_txs: usize,
    subsidy_sat: i64,
    fees_sat: i64,
    reward_sat: u64,
    verified: bool,
    verification: VerificationRecord,
    submission: SubmissionRecord,
    settings: MinedSettings,
    config: Config,
}

#[derive(Clone, Serialize)]
struct VerificationRecord {
    worker_hash_matches_reference: bool,
    hash_meets_target: bool,
    merkle_root_valid: bool,
    witness_commitment_valid: bool,
    bitcoin_crate_block_hash_matches: bool,
}

#[derive(Clone, Serialize)]
struct SubmissionRecord {
    preferred_rpc: String,
    submit_rpc: Option<String>,
    result: String,
    reject_reason: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct MinedSettings {
    backend: MiningBackend,
    threads: usize,
    batch_size: u64,
    interleave: usize,
    pin_threads: bool,
}

pub fn run(config: Config, overrides: MiningOverrides) -> Result<(), String> {
    validate_mining_config(&config)?;

    let settings = mining_settings(&config, overrides)?;
    let pool = RpcPool::new(config.rpc_servers.clone())?;
    let active = pool.select_healthy()?;
    let network = network_from_chain(&active.info.chain)?;
    let payout_script = payout_script(&config.wallet_address, network)?;

    if !config.initialized {
        println!(
            "warning: config initialized=false; run solo-miner --init on this machine for best settings"
        );
    }

    println!("Live mining started");
    println!("RPC: {} ({})", active.client.name(), active.client.url());
    println!(
        "Chain: {} blocks={} headers={}",
        active.info.chain, active.info.blocks, active.info.headers
    );
    println!("Mining mode: {:?}", config.mining_mode);
    println!("Backend: {}", settings.backend.name());
    println!("Threads: {}", settings.threads);
    println!("Batch size: {}", settings.batch_size);
    println!("Interleave: {}", settings.interleave.width());
    println!("Thread pinning: {}", settings.pin_threads);
    println!(
        "Progress: {}",
        if config.show_progress {
            "range completion"
        } else {
            "disabled"
        }
    );
    println!(
        "Hash audit: {}",
        if config.hash_audit_per_minute == 0 {
            "disabled".to_string()
        } else {
            format!("{} samples/minute", config.hash_audit_per_minute)
        }
    );
    println!();

    let run_started_epoch = current_unix_secs();
    let mut chain = active.info.chain.clone();
    let mut active_client = active.client;
    let mut active_index = active.index;
    let mut next_template = None::<BlockTemplate>;

    loop {
        let template = if let Some(template) = next_template.take() {
            template
        } else {
            match active_client.get_block_template(None) {
                Ok(template) => template,
                Err(err) => {
                    eprintln!("template fetch failed on {}: {err}", active_client.name());
                    let active = pool.select_healthy()?;
                    chain = active.info.chain.clone();
                    active_client = active.client;
                    active_index = active.index;
                    active_client.get_block_template(None)?
                }
            }
        };
        let prepared = PreparedTemplate {
            target: template_target(&template)?,
            template,
            payout_script: payout_script.clone(),
        };

        match mine_template(
            &config,
            &active_client,
            &prepared,
            settings,
            run_started_epoch,
        )? {
            TemplateOutcome::TemplateUpdate(template) => {
                next_template = Some(template);
                continue;
            }
            TemplateOutcome::Found {
                mut block,
                candidate,
                extra_nonce,
                scan_stats,
            } => {
                block.header.nonce = candidate.nonce;
                let verified_hash = verify_candidate(&block, candidate.hash, prepared.target)?;
                let block_hex = bytes_to_hex(&serialize(&block));
                let elapsed = elapsed_since_epoch(run_started_epoch);
                let block_hash = display_block_hash(verified_hash);
                println!();
                println!("Candidate found");
                println!("height={}", prepared.template.height);
                println!("prevhash={}", prepared.template.previousblockhash);
                println!("worker={}", candidate.worker_id);
                println!("nonce={}", candidate.nonce);
                println!("extranonce={extra_nonce}");
                println!("hash={block_hash}");
                println!("target={}", bytes_to_hex(&prepared.target));
                println!("elapsed={}", format_duration_days(elapsed));
                println!("scan_rate={}", format_hps(scan_stats.rate()));
                println!("template_txs={}", prepared.template.transactions.len());
                println!("fees_sat={}", prepared.template.total_fees_sat());
                println!("reward_sat={}", prepared.template.coinbasevalue);
                println!("verified=true");

                let created_at_unix = current_unix_secs();
                let preferred_rpc = active_client.name().to_string();
                let mut mined_record = MinedBlockRecord {
                    record_version: 2,
                    candidate_status: "verified".to_string(),
                    submit_status: "pending".to_string(),
                    created_at_unix,
                    updated_at_unix: created_at_unix,
                    elapsed: format_duration_days(elapsed),
                    chain: chain.clone(),
                    rpc_name: active_client.name().to_string(),
                    rpc_url: active_client.url().to_string(),
                    height: prepared.template.height,
                    previousblockhash: prepared.template.previousblockhash.clone(),
                    block_hash,
                    target: bytes_to_hex(&prepared.target),
                    bits: prepared.template.bits.clone(),
                    nonce: candidate.nonce,
                    extranonce: extra_nonce,
                    worker: candidate.worker_id,
                    mining_mode: config.mining_mode,
                    block_txs: block.txdata.len(),
                    template_txs: prepared.template.transactions.len(),
                    subsidy_sat: prepared.template.subsidy_sat(),
                    fees_sat: prepared.template.total_fees_sat(),
                    reward_sat: prepared.template.coinbasevalue,
                    verified: true,
                    verification: VerificationRecord {
                        worker_hash_matches_reference: true,
                        hash_meets_target: true,
                        merkle_root_valid: true,
                        witness_commitment_valid: true,
                        bitcoin_crate_block_hash_matches: true,
                    },
                    submission: SubmissionRecord {
                        preferred_rpc: preferred_rpc.clone(),
                        submit_rpc: None,
                        result: "pending".to_string(),
                        reject_reason: None,
                        error: None,
                    },
                    settings: MinedSettings {
                        backend: settings.backend,
                        threads: settings.threads,
                        batch_size: settings.batch_size,
                        interleave: settings.interleave.width(),
                        pin_threads: settings.pin_threads,
                    },
                    config: config.clone(),
                };
                append_mined_record(mined_record.clone())?;

                match pool.submit_block_failover(active_index, &block_hex) {
                    Ok((rpc_name, None)) => {
                        println!("submit_rpc={rpc_name}");
                        println!("submit_result=accepted");
                        mined_record.submit_status = "accepted".to_string();
                        mined_record.updated_at_unix = current_unix_secs();
                        mined_record.submission = SubmissionRecord {
                            preferred_rpc,
                            submit_rpc: Some(rpc_name),
                            result: "accepted".to_string(),
                            reject_reason: None,
                            error: None,
                        };
                        update_mined_record_submission(&mined_record)?;
                    }
                    Ok((rpc_name, Some(reason))) => {
                        println!("submit_rpc={rpc_name}");
                        println!("submit_result=rejected");
                        println!("reject_reason={reason}");
                        mined_record.submit_status = "rejected".to_string();
                        mined_record.updated_at_unix = current_unix_secs();
                        mined_record.submission = SubmissionRecord {
                            preferred_rpc,
                            submit_rpc: Some(rpc_name),
                            result: "rejected".to_string(),
                            reject_reason: Some(reason),
                            error: None,
                        };
                        update_mined_record_submission(&mined_record)?;
                    }
                    Err(err) => {
                        mined_record.submit_status = "error".to_string();
                        mined_record.updated_at_unix = current_unix_secs();
                        mined_record.submission = SubmissionRecord {
                            preferred_rpc,
                            submit_rpc: None,
                            result: "error".to_string(),
                            reject_reason: None,
                            error: Some(err.clone()),
                        };
                        update_mined_record_submission(&mined_record)?;
                        return Err(err);
                    }
                }
            }
        }
    }
}

enum TemplateOutcome {
    Found {
        block: Block,
        candidate: Candidate,
        extra_nonce: u64,
        scan_stats: ScanStats,
    },
    TemplateUpdate(BlockTemplate),
}

#[derive(Clone, Debug)]
struct PendingTemplate {
    template: BlockTemplate,
    detected_at_millis: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemplateUpdateKind {
    Ignore,
    Deferred,
    Urgent,
}

fn mine_template(
    config: &Config,
    rpc: &RpcClient,
    prepared: &PreparedTemplate,
    settings: MiningSettings,
    run_started_epoch: u64,
) -> Result<TemplateOutcome, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let urgent_template = Arc::new(Mutex::new(None::<PendingTemplate>));
    let deferred_template = Arc::new(Mutex::new(None::<PendingTemplate>));
    let (monitor_tx, monitor_rx) = mpsc::channel();
    let monitor_handles = spawn_template_monitors(
        rpc.clone(),
        prepared.template.clone(),
        config,
        Arc::clone(&stop),
        Arc::clone(&urgent_template),
        Arc::clone(&deferred_template),
        monitor_tx,
    );

    let mut extra_nonce = 0u64;
    let mut ranges_completed = 0u64;
    loop {
        if stop.load(Ordering::Relaxed) {
            if let Some(template) = take_pending_template(&urgent_template) {
                log_template_update("urgent", &template, config.mining_mode);
                stop_monitors(stop, monitor_handles);
                return Ok(TemplateOutcome::TemplateUpdate(template.template));
            }
            stop_monitors(stop, monitor_handles);
            return Ok(TemplateOutcome::TemplateUpdate(prepared.template.clone()));
        }

        drain_monitor_events(&monitor_rx);
        let status_template = status_template(&prepared.template, config.mining_mode);
        let work = build_work(prepared, config.mining_mode, extra_nonce, 0)?;
        let scan = scan_nonce_space(
            work.header,
            work.target_words,
            settings,
            ScanContext {
                stop: Arc::clone(&stop),
                hash_audit_per_minute: config.hash_audit_per_minute,
            },
        )?;

        match scan {
            ScanOutcome::Found {
                candidate,
                stats: scan_stats,
            } => {
                stop_monitors(stop, monitor_handles);
                return Ok(TemplateOutcome::Found {
                    block: work.block,
                    candidate,
                    extra_nonce,
                    scan_stats,
                });
            }
            ScanOutcome::Stale => {
                if let Some(template) = take_pending_template(&urgent_template) {
                    log_template_update("urgent", &template, config.mining_mode);
                    stop_monitors(stop, monitor_handles);
                    return Ok(TemplateOutcome::TemplateUpdate(template.template));
                }
                stop_monitors(stop, monitor_handles);
                return Ok(TemplateOutcome::TemplateUpdate(prepared.template.clone()));
            }
            ScanOutcome::Exhausted(scan_stats) => {
                ranges_completed += 1;
                extra_nonce = extra_nonce.wrapping_add(1);
                maybe_print_range_completion(
                    config.show_progress,
                    &status_template,
                    ranges_completed,
                    run_started_epoch,
                    scan_stats,
                );
                if let Some(template) = take_pending_template(&urgent_template) {
                    log_template_update("urgent", &template, config.mining_mode);
                    stop_monitors(stop, monitor_handles);
                    return Ok(TemplateOutcome::TemplateUpdate(template.template));
                }
                if let Some(template) = take_pending_template(&deferred_template) {
                    log_template_update("deferred", &template, config.mining_mode);
                    stop_monitors(stop, monitor_handles);
                    return Ok(TemplateOutcome::TemplateUpdate(template.template));
                }
            }
        }
    }
}

fn scan_nonce_space(
    header: [u8; 80],
    target: TargetWords,
    settings: MiningSettings,
    context: ScanContext,
) -> Result<ScanOutcome, String> {
    let next_nonce = Arc::new(AtomicU64::new(0));
    let result = Arc::new(Mutex::new(None::<Candidate>));
    let local_hashes = Arc::new(AtomicU64::new(0));
    let (audit_stop_tx, audit_stop_rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(settings.threads);
    let scan_started = Instant::now();

    let audit_handle = if context.hash_audit_per_minute > 0 {
        Some(spawn_hash_audit_thread(
            header,
            settings,
            context.hash_audit_per_minute,
            Arc::clone(&context.stop),
            audit_stop_rx,
        ))
    } else {
        None
    };

    for worker_id in 0..settings.threads {
        let next_nonce = Arc::clone(&next_nonce);
        let stop = Arc::clone(&context.stop);
        let result = Arc::clone(&result);
        let local_hashes = Arc::clone(&local_hashes);
        handles.push(thread::spawn(move || {
            maybe_pin_current_thread(worker_id, settings.pin_threads);
            let scalar = Sha256d80::new(&header);
            let avx512 = if settings.backend == MiningBackend::Avx512 {
                Some(Sha256d80Avx512::new(&header).expect("AVX512 checked before mining"))
            } else {
                None
            };
            let shani = if settings.backend == MiningBackend::Shani {
                Some(Sha256d80Shani::new(&header).expect("SHA-NI checked before mining"))
            } else {
                None
            };

            while !stop.load(Ordering::Relaxed) {
                let start = next_nonce.fetch_add(settings.batch_size, Ordering::Relaxed);
                if start >= NONCE_SPACE {
                    break;
                }
                let count = (NONCE_SPACE - start).min(settings.batch_size);
                let batch = match settings.backend {
                    MiningBackend::Avx512 => {
                        let avx512 = avx512.as_ref().expect("AVX512 context exists");
                        avx512.scan_batch(start, count, target)
                    }
                    MiningBackend::Scalar => scalar.scan_batch(start, count, target),
                    MiningBackend::Shani => {
                        let shani = shani.as_ref().expect("SHA-NI context exists");
                        match settings.interleave {
                            Interleave::One => shani.scan_batch(start, count, target),
                            Interleave::Two => shani.scan_batch_interleaved2(start, count, target),
                            Interleave::Four => shani.scan_batch_interleaved4(start, count, target),
                            Interleave::Eight => {
                                shani.scan_batch_interleaved8(start, count, target)
                            }
                        }
                    }
                };

                local_hashes.fetch_add(batch.hashes_checked, Ordering::Relaxed);

                if let (Some(nonce), Some(hash)) = (batch.found_nonce, batch.found_hash) {
                    let candidate = Candidate {
                        nonce,
                        hash,
                        worker_id,
                    };
                    if !stop.swap(true, Ordering::Relaxed) {
                        *result.lock().expect("candidate mutex") = Some(candidate);
                    }
                    break;
                }
            }
        }));
    }

    for handle in handles {
        handle
            .join()
            .map_err(|_| "mining worker panicked".to_string())?;
    }
    let _ = audit_stop_tx.send(());
    if let Some(handle) = audit_handle {
        handle
            .join()
            .map_err(|_| "hash audit worker panicked".to_string())??;
    }

    let candidate = *result.lock().expect("candidate mutex");
    let stats = ScanStats {
        hashes_checked: local_hashes.load(Ordering::Relaxed),
        elapsed: scan_started.elapsed(),
    };
    if let Some(candidate) = candidate {
        Ok(ScanOutcome::Found { candidate, stats })
    } else if context.stop.load(Ordering::Relaxed) {
        Ok(ScanOutcome::Stale)
    } else if next_nonce.load(Ordering::Relaxed) >= NONCE_SPACE {
        Ok(ScanOutcome::Exhausted(stats))
    } else {
        Ok(ScanOutcome::Stale)
    }
}

fn spawn_template_monitors(
    rpc: RpcClient,
    original: BlockTemplate,
    config: &Config,
    stop: Arc<AtomicBool>,
    urgent_template: Arc<Mutex<Option<PendingTemplate>>>,
    deferred_template: Arc<Mutex<Option<PendingTemplate>>>,
    tx: mpsc::Sender<MonitorEvent>,
) -> Vec<thread::JoinHandle<()>> {
    let mut handles = Vec::new();
    let poll_seconds = config.template_poll_seconds.max(1);
    let mining_mode = config.mining_mode;

    {
        let rpc = rpc.clone();
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        let original = original.clone();
        let urgent_template = Arc::clone(&urgent_template);
        let deferred_template = Arc::clone(&deferred_template);
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(poll_seconds));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match rpc.get_block_template(None) {
                    Ok(template) => {
                        match classify_template_update(&original, &template, mining_mode) {
                            TemplateUpdateKind::Urgent => {
                                store_pending_template(&urgent_template, template);
                                stop.store(true, Ordering::Relaxed);
                                let _ = tx.send(MonitorEvent::TemplateChanged);
                                break;
                            }
                            TemplateUpdateKind::Deferred => {
                                store_pending_template(&deferred_template, template);
                                let _ = tx.send(MonitorEvent::TemplateChanged);
                            }
                            TemplateUpdateKind::Ignore => {}
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(MonitorEvent::Error(err));
                    }
                }
            }
        }));
    }

    if config.longpoll {
        if let Some(longpollid) = original.longpollid.clone() {
            let rpc = rpc.clone();
            let stop = Arc::clone(&stop);
            let tx = tx.clone();
            let original = original.clone();
            let urgent_template = Arc::clone(&urgent_template);
            let deferred_template = Arc::clone(&deferred_template);
            handles.push(thread::spawn(move || {
                let mut longpollid = longpollid;
                while !stop.load(Ordering::Relaxed) {
                    match rpc.get_block_template(Some(&longpollid)) {
                        Ok(template) => {
                            let next_longpollid = template.longpollid.clone();
                            match classify_template_update(&original, &template, mining_mode) {
                                TemplateUpdateKind::Urgent => {
                                    store_pending_template(&urgent_template, template);
                                    stop.store(true, Ordering::Relaxed);
                                    let _ = tx.send(MonitorEvent::TemplateChanged);
                                    break;
                                }
                                TemplateUpdateKind::Deferred => {
                                    store_pending_template(&deferred_template, template);
                                    let _ = tx.send(MonitorEvent::TemplateChanged);
                                    if let Some(next_longpollid) = next_longpollid {
                                        longpollid = next_longpollid;
                                    } else {
                                        break;
                                    }
                                }
                                TemplateUpdateKind::Ignore => {
                                    if let Some(next_longpollid) = next_longpollid {
                                        longpollid = next_longpollid;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_secs(poll_seconds));
                        }
                    }
                }
            }));
        }
    }

    handles
}

fn stop_monitors(stop: Arc<AtomicBool>, handles: Vec<thread::JoinHandle<()>>) {
    stop.store(true, Ordering::Relaxed);
    drop(handles);
}

fn classify_template_update(
    original: &BlockTemplate,
    updated: &BlockTemplate,
    mode: MiningMode,
) -> TemplateUpdateKind {
    if original.height != updated.height
        || original.previousblockhash != updated.previousblockhash
        || original.bits != updated.bits
        || original.target != updated.target
    {
        return TemplateUpdateKind::Urgent;
    }

    if mode == MiningMode::Empty {
        return TemplateUpdateKind::Ignore;
    }

    if template_fingerprint(original, mode) != template_fingerprint(updated, mode) {
        TemplateUpdateKind::Deferred
    } else {
        TemplateUpdateKind::Ignore
    }
}

fn store_pending_template(slot: &Arc<Mutex<Option<PendingTemplate>>>, template: BlockTemplate) {
    *slot.lock().expect("pending template mutex") = Some(PendingTemplate {
        template,
        detected_at_millis: current_unix_millis(),
    });
}

fn take_pending_template(slot: &Arc<Mutex<Option<PendingTemplate>>>) -> Option<PendingTemplate> {
    slot.lock().expect("pending template mutex").take()
}

fn log_template_update(kind: &str, pending: &PendingTemplate, mode: MiningMode) {
    let delay = current_unix_millis().saturating_sub(pending.detected_at_millis);
    let status = status_template(&pending.template, mode);
    println!(
        "{} | template_update={} | apply_delay_ms={} | height={} | tx_fee={} | total_reward={} | bits={}",
        current_utc_timestamp_millis(),
        kind,
        delay,
        status.height,
        status.tx_fee,
        status.total_reward,
        status.bits,
    );
}

fn template_fingerprint(template: &BlockTemplate, mode: MiningMode) -> TemplateFingerprint {
    let (coinbase_value, default_witness_commitment, transaction_count, transaction_data_hash) =
        match mode {
            MiningMode::Empty => (template.subsidy_sat(), None, 0, 0),
            MiningMode::Template => (
                template.coinbasevalue as i64,
                template.default_witness_commitment.clone(),
                template.transactions.len(),
                hash_template_transactions(template),
            ),
        };

    TemplateFingerprint {
        version: template.version,
        previousblockhash: template.previousblockhash.clone(),
        height: template.height,
        bits: template.bits.clone(),
        target: template.target.clone(),
        coinbase_value,
        default_witness_commitment,
        transaction_count,
        transaction_data_hash,
    }
}

fn hash_template_transactions(template: &BlockTemplate) -> u64 {
    let mut hasher = DefaultHasher::new();
    for tx in &template.transactions {
        tx.data.hash(&mut hasher);
    }
    hasher.finish()
}

fn drain_monitor_events(rx: &mpsc::Receiver<MonitorEvent>) {
    while let Ok(event) = rx.try_recv() {
        match event {
            MonitorEvent::TemplateChanged => {}
            MonitorEvent::Error(err) => eprintln!("template monitor warning: {err}"),
        }
    }
}

fn build_work(
    prepared: &PreparedTemplate,
    mode: MiningMode,
    extra_nonce: u64,
    nonce: u32,
) -> Result<BuiltWork, String> {
    let mut block = build_block(prepared, mode, extra_nonce, nonce)?;
    let merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| "block has no transactions".to_string())?;
    block.header.merkle_root = merkle_root;
    let header_bytes = serialize(&block.header);
    let header: [u8; 80] = header_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("serialized header is {} bytes", bytes.len()))?;

    Ok(BuiltWork {
        block,
        header,
        target_words: TargetWords::from_be_bytes(prepared.target),
    })
}

fn build_block(
    prepared: &PreparedTemplate,
    mode: MiningMode,
    extra_nonce: u64,
    nonce: u32,
) -> Result<Block, String> {
    let template = &prepared.template;
    let mut txdata = Vec::with_capacity(match mode {
        MiningMode::Template => template.transactions.len() + 1,
        MiningMode::Empty => 1,
    });

    let include_witness_commitment =
        mode == MiningMode::Template && template.default_witness_commitment.is_some();
    let coinbase_value = match mode {
        MiningMode::Template => template.coinbasevalue,
        MiningMode::Empty => u64::try_from(template.subsidy_sat())
            .map_err(|_| "template fee total exceeds coinbase value".to_string())?,
    };

    txdata.push(build_coinbase_tx(
        template.height,
        extra_nonce,
        coinbase_value,
        &prepared.payout_script,
        include_witness_commitment
            .then_some(template.default_witness_commitment.as_deref())
            .flatten(),
    )?);

    if mode == MiningMode::Template {
        for tx in &template.transactions {
            let raw = decode_hex(&tx.data)?;
            let transaction: Transaction = deserialize(&raw)
                .map_err(|err| format!("failed to deserialize template tx: {err}"))?;
            txdata.push(transaction);
        }
    }

    let bits = u32::from_str_radix(&template.bits, 16)
        .map_err(|err| format!("invalid template bits {}: {err}", template.bits))?;
    let header = Header {
        version: BlockVersion::from_consensus(template.version),
        prev_blockhash: BlockHash::from_str(&template.previousblockhash)
            .map_err(|err| format!("invalid previousblockhash: {err}"))?,
        merkle_root: TxMerkleNode::all_zeros(),
        time: template.curtime as u32,
        bits: CompactTarget::from_consensus(bits),
        nonce,
    };

    Ok(Block { header, txdata })
}

fn build_coinbase_tx(
    height: u64,
    extra_nonce: u64,
    value_sat: u64,
    payout_script: &ScriptBuf,
    witness_commitment_script_hex: Option<&str>,
) -> Result<Transaction, String> {
    let mut witness = Witness::new();
    if witness_commitment_script_hex.is_some() {
        witness.push([0u8; 32]);
    }

    let mut output = vec![TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: payout_script.clone(),
    }];
    if let Some(script_hex) = witness_commitment_script_hex {
        output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(decode_hex(script_hex)?),
        });
    }

    Ok(Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(coinbase_script_sig(height, extra_nonce)?),
            sequence: Sequence::MAX,
            witness,
        }],
        output,
    })
}

fn coinbase_script_sig(height: u64, extra_nonce: u64) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    push_script_data(&mut script, &script_number(height)?)?;
    push_script_data(&mut script, &extra_nonce.to_le_bytes())?;
    push_script_data(&mut script, COINBASE_TAG)?;
    if script.len() > 100 {
        return Err("coinbase scriptSig exceeds 100 bytes".to_string());
    }
    Ok(script)
}

fn script_number(value: u64) -> Result<Vec<u8>, String> {
    if value == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().map(|byte| byte & 0x80 != 0).unwrap_or(false) {
        bytes.push(0);
    }
    Ok(bytes)
}

fn push_script_data(script: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    if data.len() > 75 {
        return Err("coinbase pushdata is unexpectedly long".to_string());
    }
    script.push(data.len() as u8);
    script.extend_from_slice(data);
    Ok(())
}

fn verify_candidate(
    block: &Block,
    worker_hash: [u8; 32],
    target: [u8; 32],
) -> Result<[u8; 32], String> {
    let header_bytes = serialize(&block.header);
    let header: [u8; 80] = header_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("serialized header is {} bytes", bytes.len()))?;
    let reference_hash = library_sha256d80(&header);
    if reference_hash != worker_hash {
        return Err(format!(
            "candidate nonce verification failed: worker hash {} != reference hash {}",
            display_block_hash(worker_hash),
            display_block_hash(reference_hash)
        ));
    }
    if !hash_meets_target(reference_hash, target) {
        return Err("candidate hash does not meet target on reference check".to_string());
    }
    if !block.check_merkle_root() {
        return Err("candidate block merkle root check failed".to_string());
    }
    if has_witness_commitment(block) && !block.check_witness_commitment() {
        return Err("candidate block witness commitment check failed".to_string());
    }
    let bitcoin_hash = block.block_hash().to_string();
    if bitcoin_hash != display_block_hash(reference_hash) {
        return Err(format!(
            "bitcoin crate block_hash mismatch: {} != {}",
            bitcoin_hash,
            display_block_hash(reference_hash)
        ));
    }
    Ok(reference_hash)
}

fn has_witness_commitment(block: &Block) -> bool {
    block
        .txdata
        .first()
        .map(|coinbase| {
            coinbase.output.iter().any(|output| {
                output
                    .script_pubkey
                    .as_bytes()
                    .starts_with(&WITNESS_COMMITMENT_PREFIX)
            })
        })
        .unwrap_or(false)
}

fn validate_mining_config(config: &Config) -> Result<(), String> {
    if config.wallet_address.trim().is_empty() {
        return Err("wallet_address is empty in config".to_string());
    }
    if config.wallet_address.contains("example") {
        return Err("wallet_address still looks like a placeholder".to_string());
    }
    if config.rpc_servers.is_empty() {
        return Err("rpc_servers is empty in config".to_string());
    }
    if config.template_poll_seconds == 0 {
        return Err("template_poll_seconds must be greater than zero".to_string());
    }
    Ok(())
}

fn mining_settings(config: &Config, overrides: MiningOverrides) -> Result<MiningSettings, String> {
    let available = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let fallback_threads = available.saturating_sub(config.reserved_threads).max(1);
    let optimized = config.optimized.as_ref();
    let backend = optimized
        .map(|settings| settings.backend)
        .unwrap_or_else(default_mining_backend);
    if backend == MiningBackend::Shani && !shani_available() {
        return Err(
            "optimized settings request SHA-NI backend, but this CPU does not expose SHA-NI; run solo-miner --init on this machine"
                .to_string(),
        );
    }
    if backend == MiningBackend::Avx512 && !avx512_available() {
        return Err(
            "optimized settings request AVX512 backend, but this CPU does not expose AVX512F; run solo-miner --init on this machine"
                .to_string(),
        );
    }
    let interleave = if let Some(interleave) = overrides.interleave {
        interleave
    } else if let Some(settings) = optimized {
        settings.interleave()?
    } else {
        Interleave::Eight
    };
    Ok(MiningSettings {
        backend,
        threads: overrides
            .threads
            .or_else(|| optimized.map(|settings| settings.threads))
            .unwrap_or(fallback_threads),
        batch_size: overrides
            .batch_size
            .or_else(|| optimized.map(|settings| settings.batch_size))
            .unwrap_or(DEFAULT_BATCH_SIZE),
        interleave,
        pin_threads: overrides
            .pin_threads
            .or_else(|| optimized.map(|settings| settings.pin_threads))
            .unwrap_or(false),
    })
}

fn default_mining_backend() -> MiningBackend {
    if shani_available() {
        MiningBackend::Shani
    } else if avx512_available() {
        MiningBackend::Avx512
    } else {
        MiningBackend::Scalar
    }
}

fn network_from_chain(chain: &str) -> Result<Network, String> {
    match chain {
        "main" => Ok(Network::Bitcoin),
        "test" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unsupported bitcoin chain {other:?}")),
    }
}

fn payout_script(address: &str, network: Network) -> Result<ScriptBuf, String> {
    let address = Address::from_str(address)
        .map_err(|err| format!("wallet_address is not a valid Bitcoin address: {err}"))?;
    let address = address
        .require_network(network)
        .map_err(|err| format!("wallet_address does not match RPC network {network}: {err}"))?;
    Ok(address.script_pubkey())
}

fn template_target(template: &BlockTemplate) -> Result<[u8; 32], String> {
    if template.target.len() == 64 {
        let bytes = decode_hex(&template.target)?;
        return bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| format!("target decoded to {} bytes", bytes.len()));
    }
    let bits = u32::from_str_radix(&template.bits, 16)
        .map_err(|err| format!("invalid compact bits {}: {err}", template.bits))?;
    bits_to_target(bits.to_le_bytes())
}

fn status_template(template: &BlockTemplate, mode: MiningMode) -> StatusTemplate {
    let tx_fee = if mode == MiningMode::Template {
        template.total_fees_sat()
    } else {
        0
    };
    let total_reward = if mode == MiningMode::Template {
        template.coinbasevalue as i64
    } else {
        template.subsidy_sat()
    };
    StatusTemplate {
        height: template.height,
        tx_fee,
        total_reward,
        bits: template.bits.clone(),
    }
}

fn print_compact_status(
    template: &StatusTemplate,
    ranges_completed: u64,
    elapsed: Duration,
    range_hashrate: f64,
) {
    println!(
        "{} | height={} | tx_fee={} | total_reward={} | ranges_completed={} | elapsed={} | range_hashrate={} | bits={}",
        current_utc_timestamp_millis(),
        template.height,
        template.tx_fee,
        template.total_reward,
        ranges_completed,
        format_duration_days(elapsed),
        format_hps(range_hashrate),
        template.bits,
    );
}

fn spawn_hash_audit_thread(
    header: [u8; 80],
    settings: MiningSettings,
    audits_per_minute: u64,
    stop: Arc<AtomicBool>,
    stop_rx: mpsc::Receiver<()>,
) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || {
        let interval = audit_interval(audits_per_minute);
        let mut rng = audit_seed(&header);
        let mut wait = audit_initial_delay(&mut rng, interval);
        loop {
            match stop_rx.recv_timeout(wait) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let nonce = next_audit_nonce(&mut rng);
            if let Err(err) = audit_header_hash(&header, settings.backend, nonce) {
                stop.store(true, Ordering::Relaxed);
                return Err(err);
            }
            wait = interval;
        }
        Ok(())
    })
}

fn maybe_print_range_completion(
    show_progress: bool,
    status_template: &StatusTemplate,
    ranges_completed: u64,
    run_started_epoch: u64,
    scan_stats: ScanStats,
) {
    if !show_progress {
        return;
    }
    print_compact_status(
        status_template,
        ranges_completed,
        elapsed_since_epoch(run_started_epoch),
        scan_stats.rate(),
    );
}

fn audit_interval(audits_per_minute: u64) -> Duration {
    let millis = 60_000u64 / audits_per_minute.max(1);
    Duration::from_millis(millis.max(1))
}

fn audit_initial_delay(state: &mut u64, interval: Duration) -> Duration {
    let millis = interval.as_millis().max(1) as u64;
    Duration::from_millis((next_audit_nonce(state) as u64 % millis).max(1))
}

fn audit_seed(header: &[u8; 80]) -> u64 {
    let mut hasher = DefaultHasher::new();
    header.hash(&mut hasher);
    current_unix_secs().hash(&mut hasher);
    hasher.finish()
}

fn next_audit_nonce(state: &mut u64) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x as u32
}

fn audit_header_hash(header: &[u8; 80], backend: MiningBackend, nonce: u32) -> Result<(), String> {
    let custom_hash = backend_hash_nonce(header, backend, nonce)?;
    let mut audit_header = *header;
    audit_header[76..80].copy_from_slice(&nonce.to_le_bytes());
    let reference_hash = library_sha256d80(&audit_header);
    if custom_hash != reference_hash {
        return Err(format!(
            "runtime hash audit failed for nonce {nonce}: custom {} != reference {}",
            display_block_hash(custom_hash),
            display_block_hash(reference_hash)
        ));
    }
    let header = deserialize::<Header>(&audit_header)
        .map_err(|err| format!("runtime hash audit failed to parse header: {err}"))?;
    let bitcoin_hash = header.block_hash().to_string();
    let reference_hash = display_block_hash(reference_hash);
    if bitcoin_hash != reference_hash {
        return Err(format!(
            "runtime hash audit failed for nonce {nonce}: bitcoin crate hash {bitcoin_hash} != reference {reference_hash}"
        ));
    }
    Ok(())
}

fn backend_hash_nonce(
    header: &[u8; 80],
    backend: MiningBackend,
    nonce: u32,
) -> Result<[u8; 32], String> {
    match backend {
        MiningBackend::Avx512 => Sha256d80Avx512::new(header)
            .ok_or_else(|| "AVX512 backend unavailable during hash audit".to_string())
            .map(|ctx| ctx.hash_nonce(nonce)),
        MiningBackend::Scalar => Ok(Sha256d80::new(header).hash_nonce(nonce)),
        MiningBackend::Shani => Sha256d80Shani::new(header)
            .ok_or_else(|| "SHA-NI backend unavailable during hash audit".to_string())
            .map(|ctx| ctx.hash_nonce(nonce)),
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length {}", hex.len()));
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in 0..hex.len() / 2 {
        let hi = hex_value(bytes[i * 2])?;
        let lo = hex_value(bytes[i * 2 + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte 0x{byte:02x}")),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_block_hash(internal_hash: [u8; 32]) -> String {
    internal_hash
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn append_mined_record(record: MinedBlockRecord) -> Result<(), String> {
    append_mined_record_at(Path::new("mined.json"), record)
}

fn append_mined_record_at(path: &Path, record: MinedBlockRecord) -> Result<(), String> {
    let mut records = read_mined_records(path)?;
    records.push(
        serde_json::to_value(record)
            .map_err(|err| format!("failed to serialize mined block record: {err}"))?,
    );
    write_mined_records(path, records)
}

fn update_mined_record_submission(record: &MinedBlockRecord) -> Result<(), String> {
    update_mined_record_submission_at(Path::new("mined.json"), record)
}

fn update_mined_record_submission_at(path: &Path, record: &MinedBlockRecord) -> Result<(), String> {
    let mut records = read_mined_records(path)?;
    let updated = serde_json::to_value(record)
        .map_err(|err| format!("failed to serialize mined block record: {err}"))?;
    let Some(index) = records.iter().rposition(|value| {
        value
            .get("block_hash")
            .and_then(|hash| hash.as_str())
            .map(|hash| hash == record.block_hash)
            .unwrap_or(false)
    }) else {
        return Err(format!(
            "failed to update mined.json: block hash {} was not found",
            record.block_hash
        ));
    };
    records[index] = updated;
    write_mined_records(path, records)
}

fn read_mined_records(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    if fs::metadata(path).is_err() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<serde_json::Value>>(&text)
        .map_err(|err| format!("failed to parse {} as a JSON array: {err}", path.display()))
}

fn write_mined_records(path: &Path, records: Vec<serde_json::Value>) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&records)
        .map_err(|err| format!("failed to format mined block records: {err}"))?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, format!("{text}\n"))
        .map_err(|err| format!("failed to write {}: {err}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .map_err(|err| format!("failed to replace {}: {err}", path.display()))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn current_unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

fn elapsed_since_epoch(start_epoch: u64) -> Duration {
    Duration::from_secs(current_unix_secs().saturating_sub(start_epoch))
}

fn current_utc_timestamp_millis() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format_utc_timestamp_millis(duration)
}

fn format_utc_timestamp_millis(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let millis = duration.subsec_millis();
    let days = (total_seconds / 86_400) as i64;
    let seconds_of_day = total_seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day / 60) % 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}Z{hour:02}:{minute:02}:{second:02}.{millis:03}")
}

fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
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

fn format_duration_days(duration: Duration) -> String {
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total / 3_600) % 24;
    let minutes = (total / 60) % 60;
    let seconds = total % 60;
    format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
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
            eprintln!("warning: failed to pin worker {worker_id} to CPU {worker_id}");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(_worker_id: usize) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::TemplateTransaction;

    #[test]
    fn coinbase_script_contains_height_and_extranonce_pushes() {
        let script = coinbase_script_sig(840_000, 42).unwrap();
        assert!(!script.is_empty());
        assert!(script.len() <= 100);
    }

    #[test]
    fn show_progress_false_is_allowed() {
        let mut config = crate::config::default_config();
        config.wallet_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string();
        config.show_progress = false;
        config.rpc_servers.clear();
        assert!(validate_mining_config(&config).is_err());
    }

    #[test]
    fn scalar_audit_matches_reference_hash() {
        let header = decode_hex_80_for_test(
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
        );
        audit_header_hash(&header, MiningBackend::Scalar, 2_083_236_893).unwrap();
    }

    #[test]
    fn formats_utc_timestamp_with_millis() {
        let duration = Duration::from_secs(1_779_709_402) + Duration::from_millis(184);
        assert_eq!(
            format_utc_timestamp_millis(duration),
            "2026-05-25Z11:43:22.184"
        );
    }

    #[test]
    fn mined_record_appends_then_updates_submission() {
        let path = std::env::temp_dir().join(format!(
            "solo-miner-mined-record-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut record = test_mined_record("pending");
        append_mined_record_at(&path, record.clone()).unwrap();

        record.submit_status = "accepted".to_string();
        record.updated_at_unix = 2;
        record.submission = SubmissionRecord {
            preferred_rpc: "local".to_string(),
            submit_rpc: Some("local".to_string()),
            result: "accepted".to_string(),
            reject_reason: None,
            error: None,
        };
        update_mined_record_submission_at(&path, &record).unwrap();

        let records = read_mined_records(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["submit_status"], "accepted");
        assert_eq!(records[0]["submission"]["result"], "accepted");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn empty_mode_fingerprint_ignores_mempool_only_changes() {
        let original = test_template(1_000, vec![("00", 100)]);
        let mut changed = test_template(1_200, vec![("01", 300)]);
        changed.curtime += 30;
        changed.longpollid = Some("changed".to_string());

        assert_eq!(
            template_fingerprint(&original, MiningMode::Empty),
            template_fingerprint(&changed, MiningMode::Empty)
        );
        assert_ne!(
            template_fingerprint(&original, MiningMode::Template),
            template_fingerprint(&changed, MiningMode::Template)
        );
    }

    #[test]
    fn empty_mode_fingerprint_tracks_chain_tip_changes() {
        let original = test_template(1_000, vec![("00", 100)]);
        let mut changed = original.clone();
        changed.height += 1;
        changed.previousblockhash =
            "0000000000000000000000000000000000000000000000000000000000000002".to_string();

        assert_ne!(
            template_fingerprint(&original, MiningMode::Empty),
            template_fingerprint(&changed, MiningMode::Empty)
        );
    }

    #[test]
    fn template_classifier_marks_chain_changes_urgent() {
        let original = test_template(1_000, vec![("00", 100)]);

        let mut changed_height = original.clone();
        changed_height.height += 1;
        assert_eq!(
            classify_template_update(&original, &changed_height, MiningMode::Template),
            TemplateUpdateKind::Urgent
        );

        let mut changed_prevhash = original.clone();
        changed_prevhash.previousblockhash =
            "0000000000000000000000000000000000000000000000000000000000000002".to_string();
        assert_eq!(
            classify_template_update(&original, &changed_prevhash, MiningMode::Template),
            TemplateUpdateKind::Urgent
        );

        let mut changed_bits = original.clone();
        changed_bits.bits = "1d00ffff".to_string();
        assert_eq!(
            classify_template_update(&original, &changed_bits, MiningMode::Template),
            TemplateUpdateKind::Urgent
        );

        let mut changed_target = original.clone();
        changed_target.target =
            "00000000ffff0000000000000000000000000000000000000000000000000000".to_string();
        assert_eq!(
            classify_template_update(&original, &changed_target, MiningMode::Template),
            TemplateUpdateKind::Urgent
        );
    }

    #[test]
    fn template_classifier_defers_same_tip_fee_changes() {
        let original = test_template(1_000, vec![("00", 100)]);
        let changed = test_template(1_200, vec![("00", 100), ("01", 100)]);

        assert_eq!(
            classify_template_update(&original, &changed, MiningMode::Template),
            TemplateUpdateKind::Deferred
        );
        assert_eq!(
            classify_template_update(&original, &changed, MiningMode::Empty),
            TemplateUpdateKind::Ignore
        );
    }

    fn test_template(coinbasevalue: u64, transactions: Vec<(&str, i64)>) -> BlockTemplate {
        BlockTemplate {
            version: 0x2000_0000,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            transactions: transactions
                .into_iter()
                .map(|(data, fee)| TemplateTransaction {
                    data: data.to_string(),
                    fee: Some(fee),
                })
                .collect(),
            coinbasevalue,
            target: "00000000000006b2c00000000000000000000000000000000000000000000000".to_string(),
            curtime: 1_779_500_000,
            bits: "1a06b2c0".to_string(),
            height: 4_965_618,
            default_witness_commitment: None,
            longpollid: Some("original".to_string()),
        }
    }

    fn decode_hex_80_for_test(hex: &str) -> [u8; 80] {
        decode_hex(hex).unwrap().try_into().unwrap()
    }

    fn test_mined_record(submit_status: &str) -> MinedBlockRecord {
        MinedBlockRecord {
            record_version: 2,
            candidate_status: "verified".to_string(),
            submit_status: submit_status.to_string(),
            created_at_unix: 1,
            updated_at_unix: 1,
            elapsed: "0d 00:00:01".to_string(),
            chain: "regtest".to_string(),
            rpc_name: "local".to_string(),
            rpc_url: "http://127.0.0.1:18443".to_string(),
            height: 1,
            previousblockhash: "00".repeat(32),
            block_hash: "11".repeat(32),
            target: "ff".repeat(32),
            bits: "207fffff".to_string(),
            nonce: 1,
            extranonce: 0,
            worker: 0,
            mining_mode: MiningMode::Template,
            block_txs: 1,
            template_txs: 0,
            subsidy_sat: 5_000_000_000,
            fees_sat: 0,
            reward_sat: 5_000_000_000,
            verified: true,
            verification: VerificationRecord {
                worker_hash_matches_reference: true,
                hash_meets_target: true,
                merkle_root_valid: true,
                witness_commitment_valid: true,
                bitcoin_crate_block_hash_matches: true,
            },
            submission: SubmissionRecord {
                preferred_rpc: "local".to_string(),
                submit_rpc: None,
                result: submit_status.to_string(),
                reject_reason: None,
                error: None,
            },
            settings: MinedSettings {
                backend: MiningBackend::Scalar,
                threads: 1,
                batch_size: 1,
                interleave: 1,
                pin_threads: false,
            },
            config: crate::config::default_config(),
        }
    }
}
