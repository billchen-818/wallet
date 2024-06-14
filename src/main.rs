use anyhow::{Error, Result};
use clap::Parser;
use wallet::{generate, Subcommand, Wallet};

fn main() -> Result<(), Error> {
    let wallet: Wallet = Wallet::parse();

    match wallet.cmd {
        Subcommand::Generate => {
            _ = generate();
        }
    }

    Ok(())
}
