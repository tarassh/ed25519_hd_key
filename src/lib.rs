extern crate hmac;
extern crate sha2;
extern crate sodiumoxide;
extern crate regex;

use std::mem::transmute;
use sha2::Sha512;
use hmac::{Hmac, Mac};
use sodiumoxide::crypto::sign;
use regex::Regex;

const ED25519_CURVE: &'static str = "ed25519 seed";
pub const HARDENED_OFFSET: u32 = 0x80000000;


pub fn get_master_key(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut hmac = Hmac::<Sha512>::new(ED25519_CURVE.as_bytes()).unwrap();
    hmac.input(seed);
    let i = hmac.result().code();

    let il = i[0..32].to_vec();
    let ir = i[32..].to_vec();

    (il, ir)
}

pub fn get_public_key(private_key: &[u8]) -> Vec<u8> {
    let seed = sign::Seed::from_slice(private_key).unwrap();
    let (sign_pk, _) = sign::keypair_from_seed(&seed);

    let mut public_key = vec![0u8];
    public_key.extend(&sign_pk[..]);
    public_key
}

pub fn derive(key: &[u8], chain_code: &[u8], index: u32) -> (Vec<u8>, Vec<u8>) {
    let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
    let mut data = if index & HARDENED_OFFSET != 0 {
        let mut data = vec![0u8];
        data.extend(key);
        data
    } else {
        get_public_key(&key)
    };
    data.extend(&index_buffer);

    let mut hmac = Hmac::<Sha512>::new(&chain_code).unwrap();
    hmac.input(&data);
    let i = hmac.result().code();
    let il = i[0..32].to_vec();
    let ir = i[32..].to_vec();

    (il, ir)
}

pub fn is_valid_path(path: &str) -> bool {
    if !Regex::new(r"^m(/[0-9]+')+$").unwrap().is_match(path) {
        return false
    }

    let segments: Vec<&str> = path.split('/').collect();
    segments.iter()
            .skip(1)
            .map(|s| s.replace("'", ""))
            .all(|s| s.parse::<u32>().is_ok())
}

pub fn derive_from_path(path: &str, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if !is_valid_path(path) {
        panic!("Invalid derivation path {:?}", path);
    }

    let (mut private_key, mut chain_code) = get_master_key(&seed);
    let segments: Vec<&str> = path.split('/').collect();
    let segments = segments.iter()
        .skip(1)
        .map(|s| s.replace("'", ""))
        .map(|s| s.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    
    for segment in segments {
        let(dprivate_key, dchain_code) = derive(&private_key, &chain_code, segment + HARDENED_OFFSET);
        private_key = dprivate_key;
        chain_code = dchain_code;
    }

    (private_key, chain_code)
}