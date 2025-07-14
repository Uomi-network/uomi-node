use sp_std::prelude::*;
use scale_info::prelude::string::*;
use scale_info::prelude::format;
use miniserde::{Deserialize, Serialize};
use crate::types::{ChainConfig, RpcResponse, TransactionStatus};

/// Supported blockchain networks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedChain {
    Ethereum,
    BinanceSmartChain,
    Polygon,
    Avalanche,
    Arbitrum,
    Optimism,
    Fantom,
    Uomi,
    // Add more chains as needed
}

impl SupportedChain {
    /// Get the default Ankr RPC URL for a given chain
    pub fn get_ankr_rpc_url(&self) -> &'static str {
        match self {
            SupportedChain::Ethereum => "https://rpc.ankr.com/eth",
            SupportedChain::BinanceSmartChain => "https://rpc.ankr.com/bsc",
            SupportedChain::Polygon => "https://rpc.ankr.com/polygon",
            SupportedChain::Avalanche => "https://rpc.ankr.com/avalanche",
            SupportedChain::Arbitrum => "https://rpc.ankr.com/arbitrum",
            SupportedChain::Optimism => "https://rpc.ankr.com/optimism",
            SupportedChain::Fantom => "https://rpc.ankr.com/fantom",
            SupportedChain::Uomi => "http://localhost:9944", // Local Uomi node RPC
        }
    }

    /// Get chain ID for supported chains
    pub fn get_chain_id(&self) -> u32 {
        match self {
            SupportedChain::Ethereum => 1,
            SupportedChain::BinanceSmartChain => 56,
            SupportedChain::Polygon => 137,
            SupportedChain::Avalanche => 43114,
            SupportedChain::Arbitrum => 42161,
            SupportedChain::Optimism => 10,
            SupportedChain::Fantom => 250,
            SupportedChain::Uomi => 4386,
        }
    }

    /// Create a ChainConfig from supported chain
    pub fn to_chain_config(&self) -> Result<ChainConfig, &'static str> {
        use frame_support::BoundedVec;
        
        let name_bytes = format!("{:?}", self).as_bytes().to_vec();
        let rpc_url_bytes = self.get_ankr_rpc_url().as_bytes().to_vec();
        
        let name: BoundedVec<u8, crate::types::MaxChainNameSize> = name_bytes.try_into()
            .map_err(|_| "Chain name too long")?;
        let rpc_url: BoundedVec<u8, crate::types::MaxRpcUrlSize> = rpc_url_bytes.try_into()
            .map_err(|_| "RPC URL too long")?;

        Ok(ChainConfig {
            chain_id: self.get_chain_id(),
            name,
            rpc_url,
            is_testnet: false,
        })
    }
}

/// JSON-RPC request structure
#[derive(Serialize, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<String>,
    pub id: u32,
}

impl JsonRpcRequest {
    pub fn new(method: &str, params: Vec<String>) -> Self {
        Self {
            jsonrpc: String::from("2.0"),
            method: String::from(method),
            params,
            id: 1,
        }
    }
}

/// JSON-RPC response structure
#[derive(Deserialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<String>,
    pub error: Option<JsonRpcError>,
    pub id: u32,
}

#[derive(Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// Multi-chain RPC client
pub struct MultiChainRpcClient;

impl MultiChainRpcClient {
    /// Get chain configuration by chain ID
    pub fn get_chain_config(chain_id: u32) -> Result<ChainConfig, &'static str> {
        let supported_chain = match chain_id {
            1 => SupportedChain::Ethereum,
            56 => SupportedChain::BinanceSmartChain,
            137 => SupportedChain::Polygon,
            43114 => SupportedChain::Avalanche,
            42161 => SupportedChain::Arbitrum,
            10 => SupportedChain::Optimism,
            250 => SupportedChain::Fantom,
            4386 => SupportedChain::Uomi,
            _ => return Err("Unsupported chain ID"),
        };

        supported_chain.to_chain_config()
    }

    /// Send a signed transaction to the specified chain
    pub fn send_transaction(
        chain_config: &ChainConfig,
        signed_tx: &[u8],
    ) -> Result<RpcResponse, &'static str> {
        // Convert the raw transaction bytes to hex string
        let tx_hex = format!("0x{}", hex::encode(signed_tx));
        
        // Create JSON-RPC request
        let request = JsonRpcRequest::new("eth_sendRawTransaction", vec![tx_hex]);
        
        // Serialize the request
        let request_body = miniserde::json::to_string(&request);
        
        log::info!(
            "Sending transaction to chain {} (ID: {})", 
            String::from_utf8_lossy(&chain_config.name),
            chain_config.chain_id
        );
        
        // In a real implementation, this would make an HTTP request to the RPC endpoint
        // For now, we'll simulate the response
        Self::simulate_rpc_call(&request_body, chain_config)
    }

    /// Get transaction receipt by hash
    pub fn get_transaction_receipt(
        chain_config: &ChainConfig,
        tx_hash: &str,
    ) -> Result<RpcResponse, &'static str> {
        let request = JsonRpcRequest::new("eth_getTransactionReceipt", vec![String::from(tx_hash)]);
        let request_body = miniserde::json::to_string(&request);
        
        log::info!(
            "Getting transaction receipt for {} on chain {}", 
            tx_hash,
            String::from_utf8_lossy(&chain_config.name)
        );
        
        Self::simulate_rpc_call(&request_body, chain_config)
    }

    /// Get latest block number
    pub fn get_block_number(chain_config: &ChainConfig) -> Result<u64, &'static str> {
        let request = JsonRpcRequest::new("eth_blockNumber", vec![]);
        let request_body = miniserde::json::to_string(&request);
        
        log::info!(
            "Getting latest block number from chain {}", 
            String::from_utf8_lossy(&chain_config.name)
        );
        
        // Simulate getting block number
        // In real implementation, this would parse the hex response
        Ok(18500000) // Mock block number
    }

    /// Simulate RPC call (placeholder for actual HTTP request implementation)
    fn simulate_rpc_call(
        _request_body: &str,
        chain_config: &ChainConfig,
    ) -> Result<RpcResponse, &'static str> {
        log::info!(
            "Simulating RPC call to: {}", 
            String::from_utf8_lossy(&chain_config.rpc_url)
        );
        
        // TODO: Replace this with actual HTTP client implementation
        // This could use sp_runtime_interface to make external HTTP calls
        
        // Simulate successful transaction submission
        Ok(RpcResponse {
            tx_hash: Some(String::from("0x1234567890abcdef1234567890abcdef12345678")),
            block_hash: None,
            status: TransactionStatus::Submitted,
        })
    }

    /// Validate chain configuration
    pub fn validate_chain_config(config: &ChainConfig) -> Result<(), &'static str> {
        if config.chain_id == 0 {
            return Err("Invalid chain ID");
        }
        
        if config.name.is_empty() {
            return Err("Chain name cannot be empty");
        }
        
        if config.rpc_url.is_empty() {
            return Err("RPC URL cannot be empty");
        }
        
        // Basic URL validation
        let url_str = String::from_utf8_lossy(&config.rpc_url);
        if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
            return Err("Invalid RPC URL format");
        }
        
        Ok(())
    }
}

/// Transaction builder for different chains
pub struct TransactionBuilder;

impl TransactionBuilder {
    /// Build an Ethereum-compatible transaction
    pub fn build_ethereum_transaction(
        to: &str,
        value: u64,
        data: &[u8],
        gas_limit: u64,
        gas_price: u64,
        nonce: u64,
        chain_id: u32,
    ) -> Vec<u8> {
        // This is a simplified transaction builder
        // In a real implementation, this would properly encode the transaction
        // according to EIP-155 or EIP-1559 standards
        
        log::info!(
            "Building transaction: to={}, value={}, gas_limit={}, chain_id={}",
            to, value, gas_limit, chain_id
        );
        
        // Mock transaction data - replace with proper RLP encoding
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(&nonce.to_be_bytes());
        tx_data.extend_from_slice(&gas_price.to_be_bytes());
        tx_data.extend_from_slice(&gas_limit.to_be_bytes());
        tx_data.extend_from_slice(to.as_bytes());
        tx_data.extend_from_slice(&value.to_be_bytes());
        tx_data.extend_from_slice(data);
        tx_data.extend_from_slice(&chain_id.to_be_bytes());
        
        tx_data
    }
}
