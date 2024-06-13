use std::{cmp, io::Read};

use blake2::VarBlake2b;
use digest::{Update, VariableOutput};
use num_bigint::BigInt;

#[derive(Clone)]
pub struct PubkeyMatcher {
    req: Vec<u8>,
    mask: Vec<u8>,
    prefix_len: usize,
    prefix: String,
    prefix_decoded: Vec<u8>,
}


//pub struct PubkeyMatcher {
//    max_address_value: u64,
//    prefix: String,
//    prefix_decoded: Vec<u8>,
//}

//impl PubkeyMatcher {
//
//    pub fn new(prefix: String) -> PubkeyMatcher {
//        assert!(prefix.len() >= 1 && prefix.len() <= 8);
//
//        let prefix_decoded = base32::decode(base32::Alphabet::RFC4648 { padding: (true) }, &prefix).unwrap();
//        println!("Pub-Key byte prefix is: {:?}", prefix_decoded);
//        println!("prefix is: {:?}", prefix);
//
//        PubkeyMatcher {
//            max_address_value: max_address(prefix.len()),
//            prefix,
//            prefix_decoded,
//        }
//    }
//
//    pub fn matches(&self, pubkey: [u8; 32]) -> bool {
//        return self.prefix_decoded == pubkey[..self.prefix_decoded.len()]
//    }
//
//    pub fn starts_with(&self, address: String) -> bool {
//        address.starts_with(&self.prefix)
//    }
//}

impl PubkeyMatcher {
    pub fn new(mut req: Vec<u8>, mut mask: Vec<u8>, prefix: String) -> PubkeyMatcher {

        let prefix_decoded = base32::decode(base32::Alphabet::RFC4648 { padding: (true) }, &prefix).unwrap();
        println!("Pub-Key byte prefix is: {:?}", prefix_decoded);
        println!("Pub-Key byte prefix is in bytes: {:?}", prefix_decoded.bytes());
        println!("prefix is: {:?}", prefix);

        for character in &prefix_decoded {
            println!("{}, is {:?}", character, format!("0{:b} ", character));
        }



        debug_assert!(req.iter().zip(mask.iter()).all(|(&r, &m)| r & !m == 0));
        let prefix_len = mask
            .iter()
            .enumerate()
            .rev()
            .find(|&(_i, &m)| m != 0)
            .map(|(i, _m)| i + 1)
            .unwrap_or(0);
        assert!(prefix_len <= 37);

        println!(" Start new PubkeyMatcher ========================================================================================================================== \n");
        println!("Req {:?}", req);
        println!("Mask {:?}", mask);
        req.truncate(prefix_len);
        mask.truncate(prefix_len);
        println!("Truncate Req {:?}", req);
        println!("Truncate Mask {:?}", mask);
        println!(" End new PubkeyMatcher ========================================================================================================================== \n");

        assert!(req.len() >= prefix_len);
        assert!(mask.len() >= prefix_len);
        PubkeyMatcher {
            req: req,
            mask: mask,
            prefix_len,
            prefix,
            prefix_decoded,
        }
    }


    pub fn matches_test(&self, pubkey: [u8; 32]) -> bool {
        return self.prefix_decoded == pubkey[..self.prefix_decoded.len()]
    }

    pub fn starts_with(&self, address: String) -> bool {
        address.starts_with(&self.prefix)
    }

    #[allow(dead_code)]
    pub fn req(&self) -> &[u8] {
        &self.req
    }

    #[allow(dead_code)]
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    #[allow(dead_code)]
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub fn matches(&self, pubkey: &[u8; 32]) -> bool {
        for i in 0..cmp::min(self.prefix_len, 32) {
            if pubkey[i] & self.mask[i] != self.req[i] {
                return false;
            }
        }

        if self.prefix_len > 32 {
            let mut checksum = [0u8; 5];
            let mut hasher = VarBlake2b::new(checksum.len()).unwrap();
            hasher.update(pubkey as &[u8]);
            hasher.finalize_variable(|h| checksum.copy_from_slice(h));
            for i in 32..self.prefix_len {
                if checksum[4 - (i - 32)] & self.mask[i] != self.req[i] {
                    return false;
                }
            }
        }
        true
    }

    pub fn estimated_attempts(&self) -> BigInt {
        let mut bits_in_mask = 0;
        for byte in &self.mask {
            bits_in_mask += byte.count_ones() as usize;
        }
        BigInt::from(1) << bits_in_mask
    }
}
