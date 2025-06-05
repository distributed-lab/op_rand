use secp256k1::{
    PublicKey, Secp256k1, SecretKey, Signing,
    hashes::{Hash, sha256},
    rand,
};

use rand::seq::IteratorRandom;

pub struct FirstRankCommitment {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl FirstRankCommitment {
    pub fn inner(&self) -> (SecretKey, PublicKey) {
        (self.secret_key, self.public_key)
    }
}

pub struct ThirdRankCommitment {
    public_key: PublicKey,
}

impl ThirdRankCommitment {
    pub fn inner(&self) -> PublicKey {
        self.public_key
    }
}

/// Second rank commitments are intermediate and are only used to generate the third rank commitments.
pub struct Commitments {
    first_rank_commitments: Vec<FirstRankCommitment>,
    third_rank_commitments: Vec<ThirdRankCommitment>,
}

impl Commitments {
    pub fn generate<C: Signing, R: rand::Rng + ?Sized>(
        n: usize,
        ctx: &Secp256k1<C>,
        rng: &mut R,
    ) -> Result<Self, secp256k1::Error> {
        let first_rank_commitments = (0..n)
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
}
