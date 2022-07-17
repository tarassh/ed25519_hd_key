extern crate hmac;
extern crate sha2;
extern crate sodiumoxide;
extern crate regex;

use std::mem::transmute;
use sha2::Sha512;
use hmac::{Hmac, Mac};
use sodiumoxide::crypto::sign;
use regex::Regex;
use std::convert::TryInto;

const ED25519_CURVE: &'static str = "ed25519 seed";
pub const HARDENED_OFFSET: u32 = 0x80000000;


pub fn get_master_key(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hmac = Hmac::<Sha512>::new_from_slice(ED25519_CURVE.as_bytes()).unwrap();
    hmac.update(seed);
    let i = hmac.finalize().into_bytes();
    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&i[0..32]);
    ir.copy_from_slice(&i[32..64]);

    (il, ir)
}

pub fn get_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let seed = sign::Seed::from_slice(private_key).unwrap();
    let (sign_pk, _) = sign::keypair_from_seed(&seed);

    let mut public_key = [0u8; 32];
    public_key[0..32].copy_from_slice(&sign_pk[..]);
    public_key.try_into().unwrap()
}

pub fn derive(key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
    let mut data = [0u8; 37];

    if index & HARDENED_OFFSET != 0 {
        data[1..33].copy_from_slice(key);
    } else {
        let pkey = get_public_key(&key);
        data[0..32].copy_from_slice(&pkey);
    };
    data[33..37].copy_from_slice(&index_buffer);

    let mut hmac = Hmac::<Sha512>::new_from_slice(&chain_code[..]).unwrap();
    hmac.update(&data);
    let i = hmac.finalize().into_bytes();
    let il = i[0..32].try_into().unwrap();
    let ir = i[32..].try_into().unwrap();

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

pub fn derive_from_path(path: &str, seed: &[u8]) -> ([u8; 32], [u8; 32]) {
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