use eyre::{Result, eyre};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Esplora client for interacting with esplora-tapyrus API
#[derive(Clone)]
pub struct EsploraClient {
    client: Client,
    base_url: String,
}

/// UTXO information returned by the API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub status: UtxoStatus,
    pub value: u64,
}

/// Status information for a UTXO
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

impl EsploraClient {
    /// Create a new EsploraClient instance
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Get UTXOs for a specific address
    ///
    /// # Arguments
    /// * `address` - The address to get UTXOs for
    ///
    /// # Returns
    /// A vector of UTXO information
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let url = format!("{}/address/{}/utxo", self.base_url, address);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| eyre!("Failed to send request to {}: {}", url, e))?;

        if !response.status().is_success() {
            return Err(eyre!(
                "API request failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let utxos: Vec<Utxo> = response
            .json()
            .await
            .map_err(|e| eyre!("Failed to parse UTXO response: {}", e))?;

        Ok(utxos)
    }

    /// Broadcast a raw transaction to the network
    ///
    /// # Arguments
    /// * `raw_tx_hex` - The raw transaction as a hex string
    ///
    /// # Returns
    /// The transaction ID of the broadcasted transaction
    pub async fn broadcast_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(raw_tx_hex.to_string())
            .send()
            .await
            .map_err(|e| eyre!("Failed to send broadcast request to {}: {}", url, e))?;

        if !response.status().is_success() {
            return Err(eyre!(
                "Transaction broadcast failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        // The API returns just the txid as a string
        let txid = response
            .text()
            .await
            .map_err(|e| eyre!("Failed to read txid response: {}", e))?
            .trim()
            .to_string();

        Ok(txid)
    }
}
