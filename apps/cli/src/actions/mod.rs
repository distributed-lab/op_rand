use clap::{Parser, Subcommand};
use clap_verbosity::Verbosity;
use color_eyre::eyre;
use std::path::PathBuf;
use tracing_log::AsTrace;

use crate::{
    actions::{
        accept_challenge::AcceptChallengeArgs, challenge_info::ChallengeInfoArgs,
        complete_challenge::CompleteChallengeArgs, create_challenge::CreateChallengeArgs,
        try_spend::TrySpendArgs,
    },
    context::Context,
};
mod accept_challenge;
mod balance;
mod challenge_info;
mod complete_challenge;
mod create_challenge;
mod try_spend;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity,

    #[command(subcommand)]
    pub command: Commands,

    #[clap(short, long, default_value = "config.toml")]
    pub config: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a challenge
    CreateChallenge(CreateChallengeArgs),

    /// Accept a challenge
    AcceptChallenge(AcceptChallengeArgs),

    /// Complete a challenge
    CompleteChallenge(CompleteChallengeArgs),

    /// Try to spend a challenge
    TrySpend(TrySpendArgs),

    /// Info about a challenge
    Info(ChallengeInfoArgs),

    /// Get wallet balance
    Balance,
}

impl Cli {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(self.verbosity.log_level_filter().as_trace())
            .init();

        let context = Context::new(self.config);
        execute_command(self.command, context).await
    }
}

async fn execute_command(command: Commands, context: Context) -> eyre::Result<()> {
    use Commands as Cmd;
    match command {
        Cmd::CreateChallenge(cmd) => create_challenge::run(cmd, context).await,
        Cmd::AcceptChallenge(cmd) => accept_challenge::run(cmd, context).await,
        Cmd::CompleteChallenge(cmd) => complete_challenge::run(cmd, context).await,
        Cmd::TrySpend(cmd) => try_spend::run(cmd, context).await,
        Cmd::Info(cmd) => challenge_info::run(cmd).await,
        Cmd::Balance => balance::run(context).await,
    }
}
