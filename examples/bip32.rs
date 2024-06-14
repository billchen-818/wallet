use anyhow::Error;
use base58::ToBase58;
use bip32::{Mnemonic, XPrv};
use rand_core::OsRng;
use ripemd::{Digest, Ripemd160};
use sha256::digest;
use std::io::Read;

fn main() -> Result<(), Error> {
    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());

    // 助记词
    println!("{}", mnemonic.phrase());

    // 种子
    let seed = mnemonic.to_seed("password");

    let seed_str = hex::encode(seed.as_bytes());

    println!("种子: 0x{}", seed_str.as_str());

    // 主私钥
    let root_xprv = XPrv::new(&seed);

    let prikey = root_xprv.clone().expect("REASON").to_bytes();

    let hs = hex::encode(prikey);
    println!("主私钥:0x{}", hs.as_str());

    // 主公钥
    let root_pub = root_xprv.expect("REASON").public_key();

    let pubkey = root_pub.to_bytes();

    let hs = hex::encode(pubkey);
    println!("主公钥:0x{}", hs.as_str());

    let child_path = "m/44'/60'/0'/0";

    let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()?)?;

    let prikey = child_xprv.to_bytes();

    let hs = hex::encode(prikey);
    println!("子私钥:0x{}", hs.as_str());

    let child_pub = child_xprv.public_key();

    let pubkey = child_pub.to_bytes();

    let hs = hex::encode(pubkey);
    println!("子公钥:{}", hs.as_str());

    // 1 步 公钥进行sha256哈希

    let hh = digest(&pubkey);
    println!("hh: {}", hh);

    // 2 进行ripemd160 hash
    let mut hasher = Ripemd160::new();

    hasher.update(hh);

    let result = hasher.finalize();

    let result = result;

    let ss = hex::encode(result);

    println!("{}", ss.as_str());

    // 3、将00加在第二步后面
    let ss = "00".to_owned() + ss.as_str();

    println!("ss: {}", ss.as_str());

    let dd = hex::decode(ss.clone())?;

    let dd = dd.as_slice();

    println!("{:?}", dd);

    // 4、进行双hash

    let l1 = digest(dd);

    // let l1 = l1.as_bytes();
    println!("l1: {}", l1);

    let l1 = hex::decode(l1)?;

    println!("l1: {:?}", l1);

    let l2 = digest(l1);

    println!("l2: {}", l2);

    let l2 = &l2[0..8];

    println!("l2: {}", l2);

    let ss = ss + l2;

    println!("ss: {}", ss);

    let ss = hex::decode(ss)?;

    // let ss = ss.as_bytes();

    println!("ss: {:?}", ss);

    let address = ss.to_base58();

    println!("address: {}", address);

    Ok(())
}
