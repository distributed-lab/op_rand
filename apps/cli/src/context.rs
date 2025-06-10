use std::path::PathBuf;
use std::time::Duration;

use crate::{config::Config, esplora::EsploraClient};
use bitcoin::secp256k1::{All, Secp256k1};
use color_eyre::{eyre, eyre::Context as _};
use indicatif::{ProgressBar, ProgressStyle};

/// Context is a struct which holds all information that could be used globally, like info from
/// configuration file. All the data taken from context is evaluated lazily, so it's not a problem
/// to create it once and use it everywhere.
pub struct Context {
    /// Stored path to configuration file, ti lazy load it when needed.
    config_path: PathBuf,

    /// Global secp256k1 context, used for signing and verifying signatures.
    secp_ctx: Secp256k1<All>,

    /// Loaded configuration file.
    config: Option<Config>,

    /// Esplora client
    esplora_client: Option<EsploraClient>,
}

impl Context {
    pub fn new(config: PathBuf) -> Self {
        let secp_ctx = Secp256k1::new();

        Self {
            config_path: config,
            secp_ctx,
            config: None,
            esplora_client: None,
        }
    }

    pub fn config(&mut self) -> eyre::Result<Config> {
        if let Some(config) = &self.config {
            return Ok(config.clone());
        }

        let cfg = Config::from_path(self.config_path.clone()).wrap_err("Failed to load config")?;

        self.config = Some(cfg.clone());

        Ok(cfg)
    }

    pub fn secp_ctx(&self) -> &Secp256k1<All> {
        &self.secp_ctx
    }

    pub fn esplora_client(&mut self) -> eyre::Result<EsploraClient> {
        if let Some(client) = &self.esplora_client {
            return Ok(client.clone());
        }

        let cfg = Config::from_path(self.config_path.clone()).wrap_err("Failed to load config")?;
        let client = EsploraClient::new(cfg.esplora_url);
        self.esplora_client = Some(client.clone());

        Ok(client)
    }
}

/// Setups a progress bar
pub fn setup_progress_bar(message: String) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {spinner:.red} {msg}")
            .unwrap()
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                "▪▪▪▪▪",
            ]),
    );
    pb.set_message(message);

    pb
}
