use crate::benchmark::{Interleave, DEFAULT_BATCH_SIZE};
use crate::config::{Config, MiningBackend, MiningMode};
use crate::rpc::{BlockTemplate, RpcClient, RpcPool};
use crate::sha256d::{
    bits_to_target, hash_meets_target, library_sha256d80, shani_available, Sha256d80,
    Sha256d80Shani, TargetWords,
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
    TemplateChanged(BlockTemplate),
    Error(String),
}

struct ScanContext {
    stop: Arc<AtomicBool>,
    show_progress: u64,
    ranges_completed: u64,
    run_started_epoch: u64,
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

#[derive(Serialize)]
struct MinedBlockRecord {
    mined_at_unix: u64,
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
    fees_sat: i64,
    reward_sat: u64,
    submit_rpc: String,
    submit_result: String,
    submit_reject_reason: Option<String>,
    settings: MinedSettings,
    config: Config,
}

#[derive(Serialize)]
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
        if config.show_progress == 0 {
            "disabled".to_string()
        } else {
            format!("every {}s from controller thread", config.show_progress)
        }
    );
    println!();

    let run_started_epoch = current_unix_secs();
    let mut chain = active.info.chain.clone();
    let mut active_client = active.client;
    let mut active_index = active.index;

    loop {
        let template = match active_client.get_block_template(None) {
            Ok(template) => template,
            Err(err) => {
                eprintln!("template fetch failed on {}: {err}", active_client.name());
                let active = pool.select_healthy()?;
                chain = active.info.chain.clone();
                active_client = active.client;
                active_index = active.index;
                active_client.get_block_template(None)?
            }
        };
        print_template_summary("Mining template", &template, config.mining_mode);

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
            TemplateOutcome::Stale => continue,
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

                let (submit_rpc, submit_result, reject_reason) =
                    match pool.submit_block_failover(active_index, &block_hex) {
                        Ok((rpc_name, None)) => {
                            println!("submit_rpc={rpc_name}");
                            println!("submit_result=accepted");
                            (rpc_name, "accepted".to_string(), None)
                        }
                        Ok((rpc_name, Some(reason))) => {
                            println!("submit_rpc={rpc_name}");
                            println!("submit_result=rejected");
                            println!("reject_reason={reason}");
                            (rpc_name, "rejected".to_string(), Some(reason))
                        }
                        Err(err) => return Err(err),
                    };

                append_mined_record(MinedBlockRecord {
                    mined_at_unix: current_unix_secs(),
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
                    fees_sat: prepared.template.total_fees_sat(),
                    reward_sat: prepared.template.coinbasevalue,
                    submit_rpc,
                    submit_result,
                    submit_reject_reason: reject_reason.clone(),
                    settings: MinedSettings {
                        backend: settings.backend,
                        threads: settings.threads,
                        batch_size: settings.batch_size,
                        interleave: settings.interleave.width(),
                        pin_threads: settings.pin_threads,
                    },
                    config: config.clone(),
                })?;
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
    Stale,
}

fn mine_template(
    config: &Config,
    rpc: &RpcClient,
    prepared: &PreparedTemplate,
    settings: MiningSettings,
    run_started_epoch: u64,
) -> Result<TemplateOutcome, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let changed_template = Arc::new(Mutex::new(None::<BlockTemplate>));
    let (monitor_tx, monitor_rx) = mpsc::channel();
    let monitor_handles = spawn_template_monitors(
        rpc.clone(),
        prepared.template.clone(),
        config,
        Arc::clone(&stop),
        Arc::clone(&changed_template),
        monitor_tx,
    );

    let mut extra_nonce = 0u64;
    let mut ranges_completed = 0u64;
    loop {
        if stop.load(Ordering::Relaxed) {
            stop_monitors(stop, monitor_handles);
            return Ok(TemplateOutcome::Stale);
        }

        drain_monitor_events(&monitor_rx, config.mining_mode);
        let work = build_work(prepared, config.mining_mode, extra_nonce, 0)?;
        let scan = scan_nonce_space(
            work.header,
            work.target_words,
            settings,
            ScanContext {
                stop: Arc::clone(&stop),
                show_progress: config.show_progress,
                ranges_completed,
                run_started_epoch,
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
                if let Some(template) = changed_template.lock().expect("template mutex").clone() {
                    print_template_summary("Template changed", &template, config.mining_mode);
                }
                stop_monitors(stop, monitor_handles);
                return Ok(TemplateOutcome::Stale);
            }
            ScanOutcome::Exhausted(scan_stats) => {
                ranges_completed += 1;
                extra_nonce = extra_nonce.wrapping_add(1);
                maybe_print_range_completion(
                    config.show_progress,
                    ranges_completed,
                    run_started_epoch,
                    scan_stats,
                );
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
    let (progress_stop_tx, progress_stop_rx) = mpsc::channel();
    let mut handles = Vec::with_capacity(settings.threads);
    let scan_started = Instant::now();

    let progress_handle = if context.show_progress > 0 {
        Some(spawn_progress_thread(
            progress_stop_rx,
            Arc::clone(&local_hashes),
            Duration::from_secs(context.show_progress),
            context.ranges_completed,
            context.run_started_epoch,
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
    let _ = progress_stop_tx.send(());
    if let Some(handle) = progress_handle {
        handle
            .join()
            .map_err(|_| "progress worker panicked".to_string())?;
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
    changed_template: Arc<Mutex<Option<BlockTemplate>>>,
    tx: mpsc::Sender<MonitorEvent>,
) -> Vec<thread::JoinHandle<()>> {
    let mut handles = Vec::new();
    let poll_seconds = config.template_poll_seconds.max(1);
    let mining_mode = config.mining_mode;
    let original_fingerprint = template_fingerprint(&original, mining_mode);

    {
        let rpc = rpc.clone();
        let stop = Arc::clone(&stop);
        let changed_template = Arc::clone(&changed_template);
        let tx = tx.clone();
        let original_fingerprint = original_fingerprint.clone();
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(poll_seconds));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match rpc.get_block_template(None) {
                    Ok(template) => {
                        if template_fingerprint(&template, mining_mode) != original_fingerprint {
                            *changed_template.lock().expect("template mutex") =
                                Some(template.clone());
                            stop.store(true, Ordering::Relaxed);
                            let _ = tx.send(MonitorEvent::TemplateChanged(template));
                            break;
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
            let changed_template = Arc::clone(&changed_template);
            let tx = tx.clone();
            let original_fingerprint = original_fingerprint.clone();
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match rpc.get_block_template(Some(&longpollid)) {
                        Ok(template) => {
                            if template_fingerprint(&template, mining_mode) != original_fingerprint
                            {
                                *changed_template.lock().expect("template mutex") =
                                    Some(template.clone());
                                stop.store(true, Ordering::Relaxed);
                                let _ = tx.send(MonitorEvent::TemplateChanged(template));
                                break;
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

fn drain_monitor_events(rx: &mpsc::Receiver<MonitorEvent>, mode: MiningMode) {
    while let Ok(event) = rx.try_recv() {
        match event {
            MonitorEvent::TemplateChanged(template) => {
                print_template_summary("Template changed", &template, mode);
            }
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

fn print_template_summary(label: &str, template: &BlockTemplate, mode: MiningMode) {
    let fees = if mode == MiningMode::Template {
        template.total_fees_sat()
    } else {
        0
    };
    let reward = if mode == MiningMode::Template {
        template.coinbasevalue as i64
    } else {
        template.subsidy_sat()
    };
    println!(
        "{label}: height={} prevhash={} txs={} subsidy_sat={} fees_sat={} reward_sat={} bits={} target={}",
        template.height,
        template.previousblockhash,
        match mode {
            MiningMode::Template => template.transactions.len() + 1,
            MiningMode::Empty => 1,
        },
        template.subsidy_sat(),
        fees,
        reward,
        template.bits,
        template.target
    );
}

fn spawn_progress_thread(
    stop_rx: mpsc::Receiver<()>,
    local_hashes: Arc<AtomicU64>,
    interval: Duration,
    ranges_completed: u64,
    run_started_epoch: u64,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_local = local_hashes.load(Ordering::Relaxed);
        let mut last_time = Instant::now();
        loop {
            match stop_rx.recv_timeout(interval) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            let local = local_hashes.load(Ordering::Relaxed);
            let interval_hashes = local.saturating_sub(last_local);
            let interval_secs = now.duration_since(last_time).as_secs_f64().max(0.001);
            println!(
                "progress elapsed={} range_hashes={} ranges_completed={} interval_rate={}",
                format_duration_days(elapsed_since_epoch(run_started_epoch)),
                format_u64(local),
                ranges_completed,
                format_hps(interval_hashes as f64 / interval_secs)
            );
            last_local = local;
            last_time = now;
        }
    })
}

fn maybe_print_range_completion(
    show_progress: u64,
    ranges_completed: u64,
    run_started_epoch: u64,
    scan_stats: ScanStats,
) {
    if show_progress == 0 {
        return;
    }
    println!(
        "nonce range complete ranges_completed={} elapsed={} range_rate={}",
        ranges_completed,
        format_duration_days(elapsed_since_epoch(run_started_epoch)),
        format_hps(scan_stats.rate())
    );
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
    let path = "mined.json";
    let mut records = if fs::metadata(path).is_ok() {
        let text =
            fs::read_to_string(path).map_err(|err| format!("failed to read {path}: {err}"))?;
        if text.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str::<Vec<serde_json::Value>>(&text)
                .map_err(|err| format!("failed to parse {path} as a JSON array: {err}"))?
        }
    } else {
        Vec::new()
    };

    records.push(
        serde_json::to_value(record)
            .map_err(|err| format!("failed to serialize mined block record: {err}"))?,
    );
    let text = serde_json::to_string_pretty(&records)
        .map_err(|err| format!("failed to format mined block records: {err}"))?;
    let tmp_path = "mined.json.tmp";
    fs::write(tmp_path, format!("{text}\n"))
        .map_err(|err| format!("failed to write {tmp_path}: {err}"))?;
    fs::rename(tmp_path, path).map_err(|err| format!("failed to replace {path}: {err}"))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn elapsed_since_epoch(start_epoch: u64) -> Duration {
    Duration::from_secs(current_unix_secs().saturating_sub(start_epoch))
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
    fn show_progress_zero_is_allowed() {
        let mut config = crate::config::default_config();
        config.wallet_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string();
        config.show_progress = 0;
        config.rpc_servers.clear();
        assert!(validate_mining_config(&config).is_err());
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
}
