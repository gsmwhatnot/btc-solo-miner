use crate::config::RpcConfig;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct RpcClient {
    config: RpcConfig,
    timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ActiveRpc {
    pub index: usize,
    pub client: RpcClient,
    pub info: BlockchainInfo,
}

#[derive(Clone, Debug)]
pub struct RpcPool {
    servers: Vec<RpcConfig>,
    timeout: Duration,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub initialblockdownload: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockTemplate {
    pub version: i32,
    pub previousblockhash: String,
    #[serde(default)]
    pub transactions: Vec<TemplateTransaction>,
    pub coinbasevalue: u64,
    pub target: String,
    pub curtime: u64,
    pub bits: String,
    pub height: u64,
    #[serde(default)]
    pub default_witness_commitment: Option<String>,
    #[serde(default)]
    pub longpollid: Option<String>,
}

impl BlockTemplate {
    pub fn total_fees_sat(&self) -> i64 {
        self.transactions.iter().map(|tx| tx.fee.unwrap_or(0)).sum()
    }

    pub fn subsidy_sat(&self) -> i64 {
        self.coinbasevalue as i64 - self.total_fees_sat()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TemplateTransaction {
    pub data: String,
    #[serde(default)]
    pub fee: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Value,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcClient {
    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn url(&self) -> &str {
        &self.config.url
    }

    pub fn get_blockchain_info(&self) -> Result<BlockchainInfo, String> {
        self.call("getblockchaininfo", json!([]))
    }

    pub fn get_block_template(&self, longpollid: Option<&str>) -> Result<BlockTemplate, String> {
        let params = if let Some(longpollid) = longpollid {
            json!([{ "rules": ["segwit"], "longpollid": longpollid }])
        } else {
            json!([{ "rules": ["segwit"] }])
        };
        self.call("getblocktemplate", params)
    }

    pub fn submit_block(&self, block_hex: &str) -> Result<Option<String>, String> {
        let value: Value = self.call("submitblock", json!([block_hex]))?;
        if value.is_null() {
            Ok(None)
        } else if let Some(reason) = value.as_str() {
            Ok(Some(reason.to_string()))
        } else {
            Ok(Some(value.to_string()))
        }
    }

    fn call<T>(&self, method: &str, params: Value) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "solo-miner",
            "method": method,
            "params": params,
        });
        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let mut request = agent.post(&self.config.url);
        if !self.config.username.is_empty() {
            let credentials = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.config.username, self.config.password));
            request = request.set("Authorization", &format!("Basic {credentials}"));
        }
        let response = request
            .send_json(body)
            .map_err(|err| format!("RPC {} {} failed: {err}", self.config.name, method))?;
        let rpc_response: RpcResponse = response.into_json().map_err(|err| {
            format!(
                "RPC {} {} returned invalid JSON: {err}",
                self.config.name, method
            )
        })?;
        if let Some(error) = rpc_response.error {
            return Err(format!(
                "RPC {} {} error {}: {}",
                self.config.name, method, error.code, error.message
            ));
        }
        serde_json::from_value(rpc_response.result).map_err(|err| {
            format!(
                "RPC {} {} result had unexpected shape: {err}",
                self.config.name, method
            )
        })
    }
}

impl RpcPool {
    pub fn new(servers: Vec<RpcConfig>) -> Result<Self, String> {
        if servers.is_empty() {
            return Err("config must contain at least one rpc_servers entry".to_string());
        }
        Ok(Self {
            servers,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn select_healthy(&self) -> Result<ActiveRpc, String> {
        let mut errors = Vec::new();
        for (index, server) in self.servers.iter().cloned().enumerate() {
            let client = RpcClient {
                config: server,
                timeout: self.timeout,
            };
            match client.get_blockchain_info() {
                Ok(info) => {
                    if info.initialblockdownload {
                        errors.push(format!(
                            "{} is still in initial block download",
                            client.name()
                        ));
                        continue;
                    }
                    if info.headers > info.blocks + 1 {
                        errors.push(format!(
                            "{} is not caught up: blocks={} headers={}",
                            client.name(),
                            info.blocks,
                            info.headers
                        ));
                        continue;
                    }
                    return Ok(ActiveRpc {
                        index,
                        client,
                        info,
                    });
                }
                Err(err) => errors.push(err),
            }
        }
        Err(format!(
            "no healthy RPC endpoint available:\n{}",
            errors.join("\n")
        ))
    }

    pub fn submit_block_failover(
        &self,
        preferred_index: usize,
        block_hex: &str,
    ) -> Result<(String, Option<String>), String> {
        let mut order: Vec<usize> = (0..self.servers.len()).collect();
        if preferred_index < order.len() {
            order.swap(0, preferred_index);
        }

        let mut errors = Vec::new();
        for index in order {
            let client = RpcClient {
                config: self.servers[index].clone(),
                timeout: self.timeout,
            };
            match client.submit_block(block_hex) {
                Ok(result) => return Ok((client.name().to_string(), result)),
                Err(err) => errors.push(err),
            }
        }
        Err(format!(
            "submitblock failed on all RPC endpoints:\n{}",
            errors.join("\n")
        ))
    }
}
