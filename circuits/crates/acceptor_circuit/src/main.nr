// use common::{bignum::bignum::BigNum, secp256k1};
use common::{bignum::bignum::BigNum, secp256k1::curve_params::Secp256k1, utils::point_to_address};
use std::hash::sha256;

fn main(
    // Acceptor's public key
    PK_x: [u8; 32],
    PK_y: [u8; 32],
    // Acceptor's ECDSA signature
    S: [u8; 64],
    // Third rank commitments
    H1_x: pub [u8; 32],
    H1_y: pub [u8; 32],
    H2_x: pub [u8; 32],
    H2_y: pub [u8; 32],
    // Acceptor's Bitcoin address
    // It's either hash160(PK + H1) or hash160(PK + H2)
    ADDR: pub [u8; 20],
) {
    // Verify the signature
    let valid_signature = std::ecdsa_secp256k1::verify_signature(PK_x, PK_y, S, sha256(ADDR));
    assert(valid_signature);

    // Instantiate the public keys
    let PK = Secp256k1 {
        x: BigNum::from_be_bytes(PK_x),
        y: BigNum::from_be_bytes(PK_y),
        is_infinity: false,
    };

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

    let PK_H1 = PK.add(H1);
    let PK_H2 = PK.add(H2);

    let ADDR_H1 = point_to_address(PK_H1);
    let ADDR_H2 = point_to_address(PK_H2);

    let is_addr_h1 = ADDR_H1 == ADDR;
    let is_addr_h2 = ADDR_H2 == ADDR;

    assert(is_addr_h1 | is_addr_h2);
}

#[test]
fn test_main() {}
