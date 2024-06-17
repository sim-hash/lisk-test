use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar as CurveScalar;

use blake2::{Blake2b, VarBlake2b};
use digest::{FixedOutput, Update, VariableOutput};

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use ed25519_dalek::{PublicKey, SecretKey};
use sha2::Sha512;

// pub const ADDRESS_ALPHABET: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";
pub const ADDRESS_ALPHABET: &[u8] = b"234567ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum GenerateKeyType {
    PrivateKey,
    Seed,
    /// Parameter is public offset
    ExtendedPrivateKey(EdwardsPoint),
}

fn ed25519_privkey_to_pubkey(sec: &[u8; 32]) -> [u8; 32] {
    let secret_key = SecretKey::from_bytes(sec).unwrap();
    let public_key = PublicKey::from_secret::<Sha512>(&secret_key);
    public_key.to_bytes()
}

pub fn secret_to_pubkey(key_material: [u8; 32]) -> [u8; 32] {
    ed25519_privkey_to_pubkey(&key_material)
}

/// Only used when outputting addresses to user. Not for speed.
pub fn pubkey_to_address(pubkey: [u8; 32]) -> String {

    println!("=========================================================================================================");
    println!("pub key {:?}", pubkey);
    println!("=========================================================================================================");
    let mut reverse_chars = Vec::<u8>::new();
    let mut check_hash = VarBlake2b::new(5).unwrap();
    check_hash.update(&pubkey);
    let mut check = [0u8; 5];
    check_hash.finalize_variable(|h| check.copy_from_slice(h));
    let mut ext_pubkey = pubkey.to_vec();
    ext_pubkey.extend(check.iter().rev());
    let mut ext_pubkey_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ext_pubkey);
    for _ in 0..60 {
        let n: BigInt = (&ext_pubkey_int) % 32; // lower 5 bits
        reverse_chars.push(ADDRESS_ALPHABET[n.to_usize().unwrap()]);
        ext_pubkey_int = ext_pubkey_int >> 5;
    }

    let yolo = reverse_chars
        .iter()
        .rev()
        .map(|&c| c as char)
        .collect::<String>();

    //println!("Reverse {:?}", yolo);

    reverse_chars
        .iter()
//        .rev()
        .map(|&c| c as char)
        .collect::<String>()
}
