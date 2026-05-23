use crate::benchmark::Interleave;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_TEMPLATE_POLL_SECONDS: u64 = 5;
pub const DEFAULT_SHOW_PROGRESS_SECONDS: u64 = 10;
pub const DEFAULT_RESERVED_THREADS: usize = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub initialized: bool,
    pub wallet_address: String,
    #[serde(default)]
    pub mining_mode: MiningMode,
    #[serde(default = "default_template_poll_seconds")]
    pub template_poll_seconds: u64,
    #[serde(default = "default_longpoll")]
    pub longpoll: bool,
    #[serde(default = "default_show_progress")]
    pub show_progress: u64,
    #[serde(default = "default_reserved_threads")]
    pub reserved_threads: usize,
    pub rpc_servers: Vec<RpcConfig>,
    pub optimized: Option<OptimizedSettings>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MiningMode {
    #[default]
    Template,
    Empty,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpcConfig {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizedSettings {
    pub threads: usize,
    pub batch_size: u64,
    pub interleave: usize,
    pub pin_threads: bool,
    pub hashes_per_second: f64,
    pub per_thread_hashes_per_second: f64,
    pub cpu_features: CpuFeatures,
    pub benchmarked_at_unix: u64,
}

impl OptimizedSettings {
    pub fn interleave(&self) -> Result<Interleave, String> {
        Interleave::from_width(self.interleave)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CpuFeatures {
    pub sha_ni: bool,
    pub sse2: bool,
    pub ssse3: bool,
    pub sse41: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512vl: bool,
}

impl CpuFeatures {
    pub fn detect() -> Self {
        let mut features = Self::default();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            features.sha_ni = std::is_x86_feature_detected!("sha");
            features.sse2 = std::is_x86_feature_detected!("sse2");
            features.ssse3 = std::is_x86_feature_detected!("ssse3");
            features.sse41 = std::is_x86_feature_detected!("sse4.1");
            features.avx2 = std::is_x86_feature_detected!("avx2");
            features.avx512f = std::is_x86_feature_detected!("avx512f");
            features.avx512vl = std::is_x86_feature_detected!("avx512vl");
        }
        features
    }

    pub fn summary(&self) -> String {
        format!(
            "sha_ni={}, sse2={}, ssse3={}, sse4.1={}, avx2={}, avx512f={}, avx512vl={}",
            self.sha_ni, self.sse2, self.ssse3, self.sse41, self.avx2, self.avx512f, self.avx512vl
        )
    }
}

pub fn default_config() -> Config {
    Config {
        initialized: false,
        wallet_address: String::new(),
        mining_mode: MiningMode::Template,
        template_poll_seconds: DEFAULT_TEMPLATE_POLL_SECONDS,
        longpoll: true,
        show_progress: DEFAULT_SHOW_PROGRESS_SECONDS,
        reserved_threads: DEFAULT_RESERVED_THREADS,
        rpc_servers: vec![RpcConfig {
            name: "local".to_string(),
            url: "http://127.0.0.1:8332".to_string(),
            username: String::new(),
            password: String::new(),
        }],
        optimized: None,
    }
}

pub fn load_config(path: &Path) -> Result<Config, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&text).map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

pub fn load_or_default(path: &Path) -> Result<Config, String> {
    if path.exists() {
        load_config(path)
    } else {
        Ok(default_config())
    }
}

pub fn save_config(path: &Path, config: &Config) -> Result<(), String> {
    let text = serde_json::to_string_pretty(config)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))?;
    fs::write(path, format!("{text}\n"))
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn default_template_poll_seconds() -> u64 {
    DEFAULT_TEMPLATE_POLL_SECONDS
}

fn default_longpoll() -> bool {
    true
}

fn default_show_progress() -> u64 {
    DEFAULT_SHOW_PROGRESS_SECONDS
}

fn default_reserved_threads() -> usize {
    DEFAULT_RESERVED_THREADS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_old_single_rpc_shape() {
        let old = r#"{
          "wallet_address": "bc1qexample",
          "rpc": { "url": "http://127.0.0.1:8332", "username": "u", "password": "p" }
        }"#;
        assert!(serde_json::from_str::<Config>(old).is_err());
    }

    #[test]
    fn parses_new_config_shape() {
        let text = r#"{
          "initialized": true,
          "wallet_address": "bc1qexample",
          "mining_mode": "template",
          "template_poll_seconds": 5,
          "longpoll": true,
          "show_progress": 0,
          "reserved_threads": 1,
          "rpc_servers": [
            { "name": "local", "url": "http://127.0.0.1:8332", "username": "u", "password": "p" }
          ],
          "optimized": null
        }"#;
        let config = serde_json::from_str::<Config>(text).unwrap();
        assert!(config.initialized);
        assert_eq!(config.rpc_servers.len(), 1);
        assert_eq!(config.show_progress, 0);
    }
}
