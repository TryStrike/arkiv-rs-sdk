//! Read-only tests against the Rabdi testnet. Skipped unless `ARKIV_LIVE=1`, so CI stays offline.

use arkiv::attributes::Value;
use arkiv::client::{Client, QueryOptions, Select};
use arkiv::query::Query;
use arkiv::types::{Address, Key};

const CREATOR: &str = "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7";
const EPOCH_KEY: &str = "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807";

fn live() -> bool {
    let on = std::env::var("ARKIV_LIVE").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set ARKIV_LIVE=1");
    }
    on
}

#[tokio::test]
async fn get_entity_epoch() {
    if !live() {
        return;
    }
    let client = Client::rabdi().unwrap();
    let key: Key = EPOCH_KEY.parse().unwrap();
    let e = client
        .get_entity(key)
        .await
        .unwrap()
        .expect("epoch entity exists");
    assert_eq!(e.key, Some(key));
    assert_eq!(e.creator, Some(CREATOR.parse::<Address>().unwrap()));
    assert_eq!(e.schema(), Some("strike.epochs"));
    assert!(e.created_at.is_some() && e.expires_at.is_some());
    assert!(
        e.creation_flags.is_some_and(|f| f.readonly),
        "epochs are sealed readonly"
    );
    assert!(!e.attributes.is_empty());
    eprintln!("epoch attrs: {:?}", e.attributes);
}

#[tokio::test]
async fn get_entity_missing_is_none() {
    if !live() {
        return;
    }
    let client = Client::rabdi().unwrap();
    let key: Key = "0x00000000000000000000000000000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    assert!(client.get_entity(key).await.unwrap().is_none());
}

#[tokio::test]
async fn query_rounds_by_creator_limit_3() {
    if !live() {
        return;
    }
    let client = Client::rabdi().unwrap();
    let creator: Address = CREATOR.parse().unwrap();
    let q = Query::new().schema("strike.rounds").creator(creator);
    let opts = QueryOptions {
        limit: 3,
        ..QueryOptions::default()
    };
    let page = client.query(&q, &opts).await.unwrap();
    assert!(
        !page.entities.is_empty() && page.entities.len() <= 3,
        "got {}",
        page.entities.len()
    );
    for e in &page.entities {
        assert_eq!(e.creator, Some(creator));
        assert_eq!(e.schema(), Some("strike.rounds"));
        assert!(matches!(e.attr("asset"), Some(Value::Str(_))));
        assert!(matches!(e.attr("stake"), Some(Value::Dec(_))));
        assert!(matches!(e.attr("wallet"), Some(Value::Addr(_))));
    }
    eprintln!("rounds returned: {}", page.entities.len());
}

#[tokio::test]
async fn query_key_only_and_offset_paging() {
    if !live() {
        return;
    }
    let client = Client::rabdi().unwrap();
    let q = Query::new()
        .schema("strike.rounds")
        .creator(CREATOR.parse().unwrap());
    let mut o = QueryOptions {
        limit: 2,
        select: Select::key_only(),
        ..QueryOptions::default()
    };
    let first = client.query(&q, &o).await.unwrap();
    o.offset = Some(2);
    let second = client.query(&q, &o).await.unwrap();
    let a: Vec<_> = first.entities.iter().map(|e| e.key).collect();
    let b: Vec<_> = second.entities.iter().map(|e| e.key).collect();
    assert!(a.iter().all(Option::is_some));
    assert!(a.iter().all(|k| !b.contains(k)), "pages must not overlap");
}
