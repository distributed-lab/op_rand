use common::{
    bignum::bignum::BigNum,
    secp256k1::{scalar_field::ScalarField, Secp256k1, Secp256k1Fr},
    utils::{point_to_address, point_to_bytes},
};
use std::hash::sha256;

fn main(
    // First rank commitments
    a1: [u8; 32],
    a2: [u8; 32],
    // Third rank commitments
    H1_x: pub [u8; 32],
    H1_y: pub [u8; 32],
    H2_x: pub [u8; 32],
    H2_y: pub [u8; 32],
    // Challenger's public key
    PK_x: pub [u8; 32],
    PK_y: pub [u8; 32],
    // Challenger's Bitcoin address.
    // It's either hash160(PK+A1) or hash160(PK+A2)
    ADDR: pub [u8; 20],
) {
    let a1: Secp256k1Fr = BigNum::from_be_bytes(a1);
    let a2: Secp256k1Fr = BigNum::from_be_bytes(a2);

    let G = Secp256k1::one();

    let H1 = Secp256k1 {
        x: BigNum::from_be_bytes(H1_x),
        y: BigNum::from_be_bytes(H1_y),
        is_infinity: false,
    };

    let H2 = Secp256k1 {
        x: BigNum::from_be_bytes(H2_x),
        y: BigNum::from_be_bytes(H2_y),
        is_infinity: false,
    };

    let PK = Secp256k1 {
        x: BigNum::from_be_bytes(PK_x),
        y: BigNum::from_be_bytes(PK_y),
        is_infinity: false,
    };

    let A1 = G.mul(ScalarField::from_bignum(a1));
    let A2 = G.mul(ScalarField::from_bignum(a2));

    let A1_H: Secp256k1Fr = BigNum::from_be_bytes(sha256(point_to_bytes(A1)));
    let A2_H: Secp256k1Fr = BigNum::from_be_bytes(sha256(point_to_bytes(A2)));

    let A1_H_G = G.mul(ScalarField::from_bignum(A1_H));
    let A2_H_G = G.mul(ScalarField::from_bignum(A2_H));

    assert(A1_H_G == H1);
    assert(A2_H_G == H2);

    let PK_A1 = PK.add(A1);
    let PK_A2 = PK.add(A2);

    let addr_a1 = point_to_address(PK_A1);
    let addr_a2 = point_to_address(PK_A2);

    let is_addr_a1 = addr_a1 == ADDR;
    let is_addr_a2 = addr_a2 == ADDR;

    assert(is_addr_a1 | is_addr_a2);
}
#[test]
fn test_main() {}
