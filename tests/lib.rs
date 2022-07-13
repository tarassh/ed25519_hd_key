extern crate ed25519_hd_key;

use std::collections::BTreeMap;
use ed25519_hd_key::*;

#[test]
fn test_vectors() {
    let test_sets = test_sets();

    // let deriviation_path = vec![0, HARDENED_OFFSET + 2147483647, 1, HARDENED_OFFSET + 2147483646, 2];
    // let seed_hex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    let deriviation_path = vec![HARDENED_OFFSET + 0, 1, HARDENED_OFFSET + 2, 2, 1000000000];
    let seed_hex = "000102030405060708090a0b0c0d0e0f";
    let seed = to_byte(seed_hex);
    let (mut private_key, mut chain_code) = get_master_key(&seed);
    let public_key = get_public_key(&private_key);
    let mut path: String = "m".to_string();

    let chains = &test_sets[seed_hex];
    let chain = &chains[&path];
    assert_eq!(to_hex_string(&chain_code), chain["chain"]);
    assert_eq!(to_hex_string(&private_key), chain["prv"]);
    assert_eq!(to_hex_string(&public_key), chain["pub"]);

    for mut i in deriviation_path {
        i |= HARDENED_OFFSET;

        path += "/";
        path += &format!("{:}", i & (HARDENED_OFFSET - 1));

        if i & HARDENED_OFFSET != 0 {
            path += "'";
            let (dprivate_key, dchain_code) = derive(&private_key, &chain_code, i);
            let dpublic_key = get_public_key(&dprivate_key);

            let chain = &chains[&path];
            assert_eq!(to_hex_string(&dchain_code), chain["chain"]);
            assert_eq!(to_hex_string(&dprivate_key), chain["prv"]);
            assert_eq!(to_hex_string(&dpublic_key), chain["pub"]);

            private_key = dprivate_key;
            chain_code = dchain_code;
        }
    }
}

#[test]
fn test_derive_from_path() {
    let test_sets = test_sets();
    let seed_hex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    let seed = to_byte(seed_hex);
    let path = "m/0'/2147483647'";

    let (private_key, chain_code) = derive_from_path(&path, &seed);
    let public_key = get_public_key(&private_key);

    let chain = &test_sets[seed_hex][path];

    assert_eq!(to_hex_string(&private_key), chain["prv"]);
    assert_eq!(to_hex_string(&chain_code), chain["chain"]);
    assert_eq!(to_hex_string(&public_key), chain["pub"]);
}


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

    for (_, byte) in hex.bytes().enumerate() {
        buf <<= 4;

        match byte {
            b'A'..=b'F' => buf |= byte - b'A' + 10,
            b'a'..=b'f' => buf |= byte - b'a' + 10,
            b'0'..=b'9' => buf |= byte - b'0',
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

fn test_sets() -> BTreeMap<String, BTreeMap<String, BTreeMap<String,String>>> {
    let mut chains: BTreeMap<_, BTreeMap<_,_>> = BTreeMap::new();
    let mut chainset: BTreeMap<_, BTreeMap<_, BTreeMap<_,_>>> = BTreeMap::new();

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb".to_string());
    keys.insert("prv".to_string(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7".to_string());
    keys.insert("pub".to_string(), "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed".to_string());

    chains.insert("m".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69".to_string());
    keys.insert("prv".to_string(), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3".to_string());
    keys.insert("pub".to_string(), "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c".to_string());

    chains.insert("m/0'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14".to_string());
    keys.insert("prv".to_string(), "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2".to_string());
    keys.insert("pub".to_string(), "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187".to_string());

    chains.insert("m/0'/1'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c".to_string());
    keys.insert("prv".to_string(), "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9".to_string());
    keys.insert("pub".to_string(), "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1".to_string());

    chains.insert("m/0'/1'/2'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc".to_string());
    keys.insert("prv".to_string(), "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662".to_string());
    keys.insert("pub".to_string(), "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c".to_string());

    chains.insert("m/0'/1'/2'/2'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230".to_string());
    keys.insert("prv".to_string(), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793".to_string());
    keys.insert("pub".to_string(), "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a".to_string());

    chains.insert("m/0'/1'/2'/2'/1000000000'".to_string(), keys);

    chainset.insert("000102030405060708090a0b0c0d0e0f".to_string(), chains);

    let mut chains: BTreeMap<_, BTreeMap<_,_>> = BTreeMap::new();

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b".to_string());
    keys.insert("prv".to_string(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012".to_string());
    keys.insert("pub".to_string(), "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a".to_string());

    chains.insert("m".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d".to_string());
    keys.insert("prv".to_string(), "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635".to_string());
    keys.insert("pub".to_string(), "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037".to_string());

    chains.insert("m/0'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f".to_string());
    keys.insert("prv".to_string(), "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4".to_string());
    keys.insert("pub".to_string(), "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d".to_string());

    chains.insert("m/0'/2147483647'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90".to_string());
    keys.insert("prv".to_string(), "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c".to_string());
    keys.insert("pub".to_string(), "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45".to_string());

    chains.insert("m/0'/2147483647'/1'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a".to_string());
    keys.insert("prv".to_string(), "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72".to_string());
    keys.insert("pub".to_string(), "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b".to_string());

    chains.insert("m/0'/2147483647'/1'/2147483646'".to_string(), keys);

    let mut keys = BTreeMap::new();
    keys.insert("chain".to_string(), "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4".to_string());
    keys.insert("prv".to_string(), "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d".to_string());
    keys.insert("pub".to_string(), "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0".to_string());

    chains.insert("m/0'/2147483647'/1'/2147483646'/2'".to_string(), keys);

    chainset.insert("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542".to_string(), chains);

    chainset
}