use std::path::PathBuf;

use bitcoin::{Network, PrivateKey};
use color_eyre::eyre;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Serialize)]
pub struct Config {
    pub private_key: PrivateKey,

    pub esplora_url: String,

    pub network: Network,
}

impl Config {
    pub fn from_path(path: PathBuf) -> eyre::Result<Self> {
        let config = config::Config::builder()
            .add_source(config::File::from(path))
            .build()?;

        Ok(config.try_deserialize()?)
    }
}
