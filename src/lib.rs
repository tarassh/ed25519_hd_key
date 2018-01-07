extern crate hmac;
extern crate sha2;
extern crate sodiumoxide;

use std::mem::transmute;
use sha2::Sha512;
use hmac::{Hmac, Mac};
use sodiumoxide::crypto::sign;

const ED25519_CURVE: &'static str = "ed25519 seed";
const HARDENED_OFFSET: u32 = 0x80000000;


pub fn get_master_key(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut hmac = Hmac::<Sha512>::new(ED25519_CURVE.as_bytes()).unwrap();
    hmac.input(seed);
    let i = hmac.result().code();

    let il = i[0..32].to_vec();
    let ir = i[32..].to_vec();

    (il, ir)
}

pub fn ckd_priv(key: Vec<u8>, chain_code: Vec<u8>, index: u32) -> (Vec<u8>, Vec<u8>) {
    let index_buffer: [u8; 4] = unsafe { transmute(index.to_be()) };
    let mut data = vec![0u8];
    data.extend(&key);
    data.extend(&index_buffer);

    let mut hmac = Hmac::<Sha512>::new(&chain_code).unwrap();
    hmac.input(&data);
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

pub fn derive(key: &Vec<u8>, chain_code: &Vec<u8>, index: u32) -> (Vec<u8>, Vec<u8>) {
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

#[cfg(test)]
mod tests {
    use ::*;

    fn to_hex_string(bytes: &Vec<u8>) -> String {
        let strs: Vec<String> = bytes.iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
        strs.join("")
    }

    fn to_byte(hex: &str) -> Vec<u8> {
        let mut b = Vec::with_capacity(hex.len() / 2);
        let mut modulus = 0;
        let mut buf = 0;

        for (idx, byte) in hex.bytes().enumerate() {
            buf <<= 4;

            match byte {
                b'A'...b'F' => buf |= byte - b'A' + 10,
                b'a'...b'f' => buf |= byte - b'a' + 10,
                b'0'...b'9' => buf |= byte - b'0',
                b' '|b'\r'|b'\n'|b'\t' => {
                    buf >>= 4;
                    continue
                }
                _ => assert!(false),
            }

            modulus += 1;
            if modulus == 2 {
                modulus = 0;
                b.push(buf);
            }
        }

        match modulus {
            0 => b.into_iter().collect(),
            _ => { assert!(false); vec![]},
        }
    }

    #[test]
    fn vector() {
        let deriviation_path = vec![HARDENED_OFFSET + 0, 1, HARDENED_OFFSET + 2, 2, 1000000000];
        let seed = to_byte("000102030405060708090a0b0c0d0e0f");
        let (mut private_key, mut chain_code) = get_master_key(&seed);
        let public_key = get_public_key(&private_key);

        let mut path: String = "m".to_string();
        println!("Seed (hex): {}", to_hex_string(&seed));
        println!("* Chain {}", path);
        println!("    * chain: {}", to_hex_string(&chain_code));
        println!("    * prv: {}", to_hex_string(&private_key));
        println!("    * pub: {}", to_hex_string(&public_key));
        println!();
        

        for mut i in deriviation_path {
            i |= HARDENED_OFFSET;

            path += "/";
            path += &format!("{:}", i & (HARDENED_OFFSET - 1));

            if i & HARDENED_OFFSET != 0 {
                path += "h";
                let (dprivate_key, dchain_code) = derive(&private_key, &chain_code, i);
                let public_key = get_public_key(&dprivate_key);
                println!("* Chain {}", path);
                println!("    * chain: {}", to_hex_string(&dchain_code));
                println!("    * prv: {}", to_hex_string(&dprivate_key));
                println!("    * pub: {}", to_hex_string(&public_key));
                println!();

                private_key = dprivate_key;
                chain_code = dchain_code;
            }
        }
    }

    #[test]
    fn vector2() {
        let deriviation_path = vec![0, HARDENED_OFFSET + 2147483647, 1, HARDENED_OFFSET + 2147483646, 2];
        let seed = to_byte("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        let (mut private_key, mut chain_code) = get_master_key(&seed);
        let public_key = get_public_key(&private_key);

        let mut path: String = "m".to_string();
        println!("Seed (hex): {}", to_hex_string(&seed));
        println!("* Chain {}", path);
        println!("    * chain: {}", to_hex_string(&chain_code));
        println!("    * prv: {}", to_hex_string(&private_key));
        println!("    * pub: {}", to_hex_string(&public_key));
        println!();
        

        for mut i in deriviation_path {
            i |= HARDENED_OFFSET;

            path += "/";
            path += &format!("{:}", i & (HARDENED_OFFSET - 1));

            if i & HARDENED_OFFSET != 0 {
                path += "'";
                let (dprivate_key, dchain_code) = derive(&private_key, &chain_code, i);
                let public_key = get_public_key(&dprivate_key);
                println!("* Chain {}", path);
                println!("    * chain: {}", to_hex_string(&dchain_code));
                println!("    * prv: {}", to_hex_string(&dprivate_key));
                println!("    * pub: {}", to_hex_string(&public_key));
                println!();

                private_key = dprivate_key;
                chain_code = dchain_code;
            }
        }
    }
}
