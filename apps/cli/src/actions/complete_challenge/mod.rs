use clap::Args;
use color_eyre::eyre;

use crate::context::Context;

#[derive(Args, Debug)]
pub struct CompleteChallengeArgs {
    /// Path to the challenge JSON file
    #[clap(long, default_value = "challenge.json")]
    pub challenge_file: String,
    /// Path to the acceptor JSON file
    #[clap(long, default_value = "acceptor.json")]
    pub acceptor_file: String,
}

pub async fn run(
    CompleteChallengeArgs {
        challenge_file,
        acceptor_file,
    }: CompleteChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    Ok(())
}
