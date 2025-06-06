use common::{
    bignum::bignum::BigNum,
    secp256k1::{curve_params::{Secp256k1, Secp256k1Fq}, scalar_field::ScalarField},
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
    let a1: Secp256k1Fq = BigNum::from_be_bytes(a1);
    let a2: Secp256k1Fq = BigNum::from_be_bytes(a2);

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

    let a1_scalar: ScalarField<65> = ScalarField::from_bignum(a1);
    let a2_scalar: ScalarField<65> = ScalarField::from_bignum(a2);

    let A1 = G.mul(a1_scalar);
    let A2 = G.mul(a2_scalar);

    let A1_H: Secp256k1Fq = BigNum::from_be_bytes(sha256(point_to_bytes(A1)));
    let A2_H: Secp256k1Fq = BigNum::from_be_bytes(sha256(point_to_bytes(A2)));

    let A1_H_scalar: ScalarField<65> = ScalarField::from_bignum(A1_H);
    let A2_H_scalar: ScalarField<65> = ScalarField::from_bignum(A2_H);

    let A1_H_G = G.mul(A1_H_scalar);
    let A2_H_G = G.mul(A2_H_scalar);

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
fn test_main() {
    let a1_bytes = [
        234, 26, 63, 222, 18, 19, 17, 203, 11, 147, 188, 37, 35, 4, 191, 76, 205, 110, 223, 206,
        159, 83, 7, 127, 122, 196, 31, 65, 245, 1, 10, 82,
    ];
    let a2_bytes = [
        97, 92, 5, 27, 23, 205, 41, 114, 89, 32, 207, 74, 194, 65, 199, 186, 246, 115, 119, 97, 55,
        98, 87, 250, 75, 31, 60, 210, 153, 7, 168, 208,
    ];

    let H1_x = [
        99, 55, 46, 1, 138, 91, 108, 243, 211, 82, 189, 253, 206, 250, 203, 127, 73, 28, 40, 47,
        244, 13, 164, 113, 119, 209, 36, 169, 77, 118, 18, 192,
    ];
    let H1_y = [
        43, 253, 209, 60, 100, 47, 145, 237, 223, 35, 47, 39, 225, 35, 201, 4, 160, 178, 157, 209,
        148, 140, 159, 175, 78, 158, 140, 81, 212, 154, 84, 143,
    ];
    let H2_x = [
        63, 179, 171, 101, 192, 29, 36, 147, 111, 236, 166, 134, 54, 41, 23, 213, 118, 116, 213, 65,
        162, 16, 186, 213, 144, 114, 74, 59, 194, 56, 174, 149,
    ];
    let H2_y = [
        104, 18, 109, 126, 195, 27, 147, 151, 248, 206, 73, 46, 48, 18, 219, 85, 109, 112, 158, 105,
        206, 205, 20, 234, 202, 250, 19, 176, 127, 64, 241, 164,
    ];

    let PK_x = [
        44, 20, 131, 4, 87, 150, 172, 82, 26, 204, 95, 101, 107, 65, 198, 12, 199, 49, 50, 40, 161,
        207, 254, 99, 4, 95, 39, 46, 148, 156, 68, 35,
    ];

    let PK_y = [
        61, 91, 215, 161, 125, 104, 176, 190, 58, 137, 111, 138, 132, 175, 233, 100, 219, 251, 194,
        9, 175, 64, 250, 229, 221, 238, 43, 252, 158, 36, 219, 77,
    ];

    let addr =
        [60, 230, 154, 6, 76, 115, 46, 129, 118, 221, 120, 50, 85, 94, 223, 33, 185, 48, 124, 248];

    main(a1_bytes, a2_bytes, H1_x, H1_y, H2_x, H2_y, PK_x, PK_y, addr);
}
