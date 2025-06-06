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
fn test_main() {
    let pk_x = [
        22, 219, 248, 255, 240, 33, 119, 211, 154, 79, 103, 72, 135, 251, 211, 114, 16, 48, 199, 97,
        191, 36, 118, 163, 173, 7, 103, 28, 92, 212, 43, 237,
    ];
    let pk_y = [
        163, 123, 216, 234, 192, 119, 125, 193, 82, 247, 238, 199, 207, 103, 196, 9, 45, 113, 183,
        124, 230, 231, 181, 60, 185, 211, 32, 210, 40, 165, 2, 142,
    ];
    let s = [
        255, 138, 32, 255, 132, 55, 164, 52, 49, 131, 142, 187, 28, 210, 81, 181, 20, 87, 29, 20,
        17, 117, 35, 144, 31, 60, 221, 73, 144, 30, 5, 204, 51, 136, 11, 245, 244, 252, 7, 203, 136,
        248, 128, 69, 245, 87, 170, 100, 108, 157, 58, 2, 237, 94, 101, 61, 141, 252, 145, 140, 108,
        165, 96, 8,
    ];
    let h1_x = [
        228, 216, 1, 95, 179, 232, 56, 38, 76, 93, 129, 147, 17, 19, 178, 219, 228, 237, 51, 63,
        121, 201, 153, 88, 135, 205, 12, 153, 255, 124, 116, 219,
    ];
    let h1_y = [
        17, 94, 62, 3, 122, 245, 81, 187, 122, 51, 98, 14, 235, 106, 19, 249, 128, 5, 183, 108, 228,
        255, 200, 227, 71, 119, 70, 86, 210, 67, 210, 63,
    ];
    let h2_x = [
        152, 194, 169, 105, 33, 87, 12, 95, 254, 138, 81, 118, 47, 223, 147, 117, 234, 183, 223,
        207, 176, 125, 141, 46, 196, 106, 163, 75, 37, 214, 83, 18,
    ];
    let h2_y = [
        25, 36, 187, 188, 164, 202, 42, 221, 135, 201, 247, 179, 47, 170, 125, 141, 78, 5, 18, 4, 7,
        87, 152, 146, 131, 161, 124, 253, 46, 146, 97, 10,
    ];
    let addr =
        [47, 60, 200, 126, 139, 33, 34, 138, 8, 169, 218, 176, 251, 215, 87, 66, 79, 125, 100, 116];

    main(pk_x, pk_y, s, h1_x, h1_y, h2_x, h2_y, addr);
}
