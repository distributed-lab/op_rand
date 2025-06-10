use std::str::FromStr;

use bitcoin::{
    key::Secp256k1,
    secp256k1::{
        self, PublicKey, Scalar, SecretKey, Signing,
        hashes::{Hash, sha256},
        rand,
    },
};

use rand::seq::IteratorRandom;

/// Number of commitments to create.
/// Currently only 2 commitments are supported.
pub const COMMITMENTS_COUNT: usize = 2;

/// First rank commitment.
/// This is the commitment that the challenger uses to create the deposit transaction.
#[derive(Debug, Clone)]
pub struct FirstRankCommitment {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl FromStr for FirstRankCommitment {
    type Err = secp256k1::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let secret_key = SecretKey::from_str(s)?;
        let public_key = secret_key.public_key(&Secp256k1::new());

        Ok(FirstRankCommitment {
            secret_key,
            public_key,
        })
    }
}
impl FirstRankCommitment {
    pub fn inner(&self) -> (SecretKey, PublicKey) {
        (self.secret_key, self.public_key)
    }

    pub fn add_tweak(&self, tweak: &SecretKey) -> Result<SecretKey, secp256k1::Error> {
        let scalar = Scalar::from(*tweak);
        self.secret_key.add_tweak(&scalar)
    }

    pub fn combine(&self, tweak: &PublicKey) -> Result<PublicKey, secp256k1::Error> {
        self.public_key.combine(tweak)
    }
}

/// Third rank commitment.
/// This is the commitment that the acceptor uses to create the challenge transaction.
#[derive(Debug, Clone)]
pub struct ThirdRankCommitment {
    public_key: PublicKey,
}

impl ThirdRankCommitment {
    pub fn inner(&self) -> PublicKey {
        self.public_key
    }

    pub fn combine(&self, tweak: &PublicKey) -> Result<PublicKey, secp256k1::Error> {
        self.public_key.combine(tweak)
    }
}

impl FromStr for ThirdRankCommitment {
    type Err = secp256k1::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let public_key = PublicKey::from_str(s)?;
        Ok(ThirdRankCommitment { public_key })
    }
}

/// Commitments are used to create the challenge transaction.
/// They are generated from the first rank commitments.
/// Note that the second rank commitments are not stored, they are only used to generate the
/// third rank commitments.
#[derive(Debug, Clone)]
pub struct Commitments {
    first_rank_commitments: [FirstRankCommitment; 2],
    third_rank_commitments: [ThirdRankCommitment; 2],
}

impl Commitments {
    pub fn generate<C: Signing, R: rand::Rng + ?Sized>(
        ctx: &Secp256k1<C>,
        rng: &mut R,
    ) -> Result<Self, secp256k1::Error> {
        let first_rank_commitments = (0..COMMITMENTS_COUNT)
            .map(|_| {
                let (first_rank_sk, first_rank_pk) = ctx.generate_keypair(rng);
                FirstRankCommitment {
                    secret_key: first_rank_sk,
                    public_key: first_rank_pk,
                }
            })
            .collect::<Vec<_>>();

        let second_rank_commitments = first_rank_commitments
            .iter()
            .map(|commitment| {
                let first_rank_pk = commitment.public_key.serialize();

                let second_rank_commitment_hash = sha256::Hash::hash(&first_rank_pk);
                let second_rank_commitment =
                    SecretKey::from_slice(second_rank_commitment_hash.as_byte_array())?;

                Ok(second_rank_commitment)
            })
            .collect::<Result<Vec<_>, secp256k1::Error>>()?;

        let third_rank_commitments = second_rank_commitments
            .iter()
            .map(|commitment| {
                let third_rank_pk = commitment.public_key(&ctx);

                ThirdRankCommitment {
                    public_key: third_rank_pk,
                }
            })
            .collect::<Vec<_>>();

        // TODO: we currently only support 2 commitments
        let first_rank_commitments = first_rank_commitments.try_into().unwrap();
        let third_rank_commitments = third_rank_commitments.try_into().unwrap();

        Ok(Commitments {
            first_rank_commitments,
            third_rank_commitments,
        })
    }

    pub fn pick_random_first_rank_commitment<R: rand::Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Option<&FirstRankCommitment> {
        self.first_rank_commitments.iter().choose(rng)
    }

    pub fn pick_random_third_rank_commitment<R: rand::Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Option<&ThirdRankCommitment> {
        self.third_rank_commitments.iter().choose(rng)
    }

    pub fn pick_first_rank_commitment(&self, i: usize) -> Option<&FirstRankCommitment> {
        self.first_rank_commitments.get(i)
    }

    pub fn pick_third_rank_commitment(&self, i: usize) -> Option<&ThirdRankCommitment> {
        self.third_rank_commitments.get(i)
    }

    pub fn first_rank_commitments(&self) -> &[FirstRankCommitment; COMMITMENTS_COUNT] {
        &self.first_rank_commitments
    }

    pub fn third_rank_commitments(&self) -> &[ThirdRankCommitment; COMMITMENTS_COUNT] {
        &self.third_rank_commitments
    }
}
