use anyhow::Error;
use base58::ToBase58;
use bip32::{Mnemonic, XPrv};
use clap::Parser;
use rand_core::OsRng;
use ripemd::{Digest, Ripemd160};
use sha256::digest;

#[derive(Debug, Parser)]
#[command(name = "wallet", version = "0.1", author, about)]
pub struct Wallet {
    #[command(subcommand)]
    pub cmd: Subcommand,
}

#[derive(Debug, Parser)]
pub enum Subcommand {
    #[command(name = "generate", about = "Generate a new btc wallet")]
    Generate,
}

pub fn generate() -> Result<(), Error> {
    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());
    // 助记词
    println!("助记词:{}", mnemonic.phrase());
    // 种子
    let seed = mnemonic.to_seed("password");
    let child_path = "m/44'/0'/0'/0";
    let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()?)?;
    let child_pub = child_xprv.public_key();
    // 1 步 公钥进行sha256哈希
    let hh = digest(&child_pub.to_bytes());
    // 2 进行ripemd160 hash
    let mut hasher = Ripemd160::new();
    hasher.update(hh);
    let result = hasher.finalize();
    let ss = hex::encode(result);
    // 3、将00加在第二步后面
    let ss = "00".to_owned() + ss.as_str();
    let dd = hex::decode(ss.clone())?;
    let dd = dd.as_slice();
    // 4、进行双hash
    let l1 = digest(dd);
    let l1 = hex::decode(l1)?;
    let l2 = digest(l1);
    let l2 = &l2[0..8];
    let ss = ss + l2;
    let ss = hex::decode(ss)?;
    let address = ss.to_base58();
    println!("address: {}", address);

    Ok(())
}
