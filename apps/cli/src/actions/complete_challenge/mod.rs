use clap::Args;
use color_eyre::eyre;

use crate::context::Context;

#[derive(Args, Debug)]
pub struct CompleteChallengeArgs {
    /// Proof
    #[clap(long, short)]
    pub proof: String,
}

pub async fn run(
    CompleteChallengeArgs { proof }: CompleteChallengeArgs,
    mut ctx: Context,
) -> eyre::Result<()> {
    Ok(())
}
