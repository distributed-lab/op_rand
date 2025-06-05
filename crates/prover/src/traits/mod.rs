mod prover;

pub use prover::OpRandProver;

pub struct OpRandProof {
    proof: Vec<u8>,
    vk: Vec<u8>,
}

impl OpRandProof {
    pub fn new(proof: Vec<u8>, vk: Vec<u8>) -> Self {
        Self { proof, vk }
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn vk(&self) -> &[u8] {
        &self.vk
    }
}
