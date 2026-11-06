//! Reads from the Rabdi testnet. No key needed.
//!
//! ```text
//! cargo run --example query
//! ```

use arkiv::query::{gt, Dir};
use arkiv::{AttrType, Client, Query, QueryOptions, Value};

const CREATOR: &str = "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7";
const EPOCH_KEY: &str = "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";

#[tokio::main]
async fn main() -> arkiv::Result<()> {
    let client = Client::rabdi()?;

    // One entity by key.
    if let Some(entity) = client.get_entity(EPOCH_KEY.parse()?).await? {
        println!(
            "{:?} has {} attributes",
            entity.schema(),
            entity.attributes.len()
        );
    }

    // A filtered, ordered query. The builder writes the query string for you.
    let query = Query::new()
        .schema("strike.rounds")
        .creator(CREATOR.parse()?)
        .filter(gt("settledAt", Value::U64(0)))
        .order_by("settledAt", AttrType::U64, Dir::Desc);
    println!("{}", query.build()?);

    let options = QueryOptions {
        limit: 5,
        ..QueryOptions::default()
    };
    let page = client.query(&query, &options).await?;
    println!("block {}: {} rows", page.block_number, page.entities.len());
    for e in &page.entities {
        println!("  {:?} asset={:?}", e.key, e.attr("asset"));
    }

    // Many rows. query_all pages with offset, because cursors do not survive across blocks.
    let rows = client.query_all(&query, &options, 250).await?;
    println!("{} rows in total", rows.len());
    Ok(())
}
