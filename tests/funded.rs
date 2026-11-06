//! Tests that spend gas. Ignored by default; run with
//! `ARKIV_TEST_KEY=0x... cargo test --test funded -- --ignored` using a throwaway funded Rabdi key.

use arkiv::attributes::{Attribute, Value};
use arkiv::client::{Client, ExecOptions};
use arkiv::ops::{Create, Expiry, Op};
use arkiv::signer::Signer;

fn signer() -> Signer {
    let k = std::env::var("ARKIV_TEST_KEY").expect("set ARKIV_TEST_KEY to a throwaway funded key");
    Signer::from_hex(&k).unwrap()
}

fn create(tag: &str, n: u64) -> Op {
    let attrs = vec![
        Attribute::schema(tag).unwrap(),
        Attribute::u64("n", n).unwrap().indexed().unwrap(),
        Attribute::str("note", "arkiv-rs-sdk funded test").unwrap(),
    ];
    Op::Create(
        Create::new(attrs, Expiry::blocks(600).unwrap())
            .unwrap()
            .readonly(),
    )
}

#[tokio::test]
#[ignore = "needs ARKIV_TEST_KEY"]
async fn create_one_and_read_back() {
    let (client, signer) = (Client::rabdi().unwrap(), signer());
    let out = client
        .execute(
            &signer,
            &[create("arkiv-rs-sdk.test", 1)],
            &ExecOptions::default(),
        )
        .await
        .unwrap();
    let keys = out.keys.clone();
    assert_eq!(keys.len(), 1);
    let e = client
        .get_entity(keys[0])
        .await
        .unwrap()
        .expect("entity readable after receipt");
    assert_eq!(e.creator, Some(signer.address()));
    assert!(e.creation_flags.is_some_and(|f| f.readonly));
    assert_eq!(e.attr("n"), Some(&Value::U64(1)));
}

#[tokio::test]
#[ignore = "needs ARKIV_TEST_KEY"]
async fn batch_of_five_creates_five_keys() {
    let (client, signer) = (Client::rabdi().unwrap(), signer());
    let ops: Vec<Op> = (0..5).map(|i| create("arkiv-rs-sdk.test", i)).collect();
    let out = client
        .execute(&signer, &ops, &ExecOptions::default())
        .await
        .unwrap();
    assert_eq!(out.keys.len(), 5);
}

#[tokio::test]
#[ignore = "needs ARKIV_TEST_KEY"]
async fn execute_all_splits_under_cap() {
    let (client, signer) = (Client::rabdi().unwrap(), signer());
    let ops: Vec<Op> = (0..12).map(|i| create("arkiv-rs-sdk.test", i)).collect();
    let opts = ExecOptions {
        max_calldata: 2_000,
        ..ExecOptions::default()
    };
    let outs = client.execute_all(&signer, ops, &opts).await.unwrap();
    assert!(outs.len() > 1, "a 2 KB cap must force several transactions");
    assert_eq!(outs.iter().map(|o| o.keys.len()).sum::<usize>(), 12);
}
