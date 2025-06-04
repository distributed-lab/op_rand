use crate::bignum::bignum::BigNum;
use crate::bignum::fields::secp256k1Fq::Secp256k1_Fq_Params;
use crate::secp256k1::CurveParamsTrait;

type Secp256k1BN = BigNum<3, 256, Secp256k1_Fq_Params>;

pub struct Secp256k1PartialCurveParams {}
impl CurveParamsTrait<Secp256k1BN> for Secp256k1PartialCurveParams {
    fn a() -> Secp256k1BN {
        BigNum { limbs: [0, 0, 0] }
    }
    fn b() -> Secp256k1BN {
        BigNum { limbs: [7, 0, 0] }
    }

    fn one() -> [Secp256k1BN; 2] {
        let mut y: Secp256k1BN = BigNum {
            limbs: [0x17b448a68554199c47d08ffb10d4b8, 0xda7726a3c4655da4fbfc0e1108a8fd, 0x483a],
        };
        let mut x: Secp256k1BN = BigNum {
            limbs: [0x9bfcdb2dce28d959f2815b16f81798, 0x667ef9dcbbac55a06295ce870b0702, 0x79be],
        };
        [x, y]
    }

    fn offset_generator_final() -> [Secp256k1BN; 2] {
        assert(true == false, "generator does not exist!");
        Secp256k1PartialCurveParams::one()
    }

    fn offset_generator() -> [Secp256k1BN; 2] {
        assert(true == false, "generator does not exist!");
        Secp256k1PartialCurveParams::one()
    }
}
