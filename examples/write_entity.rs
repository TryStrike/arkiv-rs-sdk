//! Writes one readonly entity to the Rabdi testnet and reads it back.
//!
//! ```text
//! ARKIV_PRIVATE_KEY=0x... cargo run --example write_entity
//! ```
//!
//! Use a throwaway testnet key with a little funding. The key is read from the environment only.

use arkiv::{Attribute, Client, Create, ExecOptions, Expiry, Op, Signer};

#[tokio::main]
async fn main() -> arkiv::Result<()> {
    let key = std::env::var("ARKIV_PRIVATE_KEY").map_err(|_| arkiv::Error::InvalidKey)?;
    let signer = Signer::from_hex(&key)?;
    let client = Client::rabdi()?;

    let attributes = vec![
        Attribute::schema("arkiv-rs-sdk.example")?,
        Attribute::str("text", "hello from arkiv-rs-sdk")?,
        Attribute::u64("n", 1)?.indexed()?,
    ];
    // 600 blocks at 2 s each is about 20 minutes.
    let create = Create::new(attributes, Expiry::blocks(600)?)?.readonly();

    let done = client
        .execute(&signer, &[Op::Create(create)], &ExecOptions::default())
        .await?;
    println!("tx {} in block {}", done.tx_hash, done.block_number);

    for key in &done.keys {
        println!("entity {key}");
        println!("explorer: https://rabdi.explorer.arkiv.network (search for the key)");
        if let Some(entity) = client.get_entity(*key).await? {
            println!(
                "read back: schema={:?} text={:?}",
                entity.schema(),
                entity.attr("text")
            );
        }
    }
    Ok(())
}
