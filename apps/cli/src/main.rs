mod actions;
mod config;
mod context;
mod esplora;
mod ui;
mod util;

use clap::Parser;

use crate::actions::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    Cli::parse().run().await
}
