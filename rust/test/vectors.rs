//! Golden vectors: fixed inputs with asserted, pinned outputs. If any of
//! these ever change, the hashing/encoding changed and every deployed
//! policy root computed under the old version is no longer reproducible.

use mlcc2::{hash_leaf_payload, LeafCollection, LeafPayload};

fn fixed_payloads() -> Vec<LeafPayload> {
    vec![
        LeafPayload { template_hash: [0x11; 32], param_commitment: [0x01; 32], leaf_flags: 0 },
        LeafPayload { template_hash: [0x22; 32], param_commitment: [0x02; 32], leaf_flags: 0 },
        LeafPayload { template_hash: [0x33; 32], param_commitment: [0x03; 32], leaf_flags: 0 },
    ]
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn golden_leaf_commitments() {
    let payloads = fixed_payloads();
    let commitments: Vec<String> = payloads.iter().map(|p| hex(&hash_leaf_payload(p))).collect();
    assert_eq!(
        commitments,
        vec![
            "93275de753e4fcbc36bd88c7edc2b701076e16dd1b1a514ed450d52346929725".to_string(),
            "1898fe4fb7f9b1d0bf29670073ed53ade6c165411f501c41f83993c792466322".to_string(),
            "c61c5e5e1de1e7490a798c88950e6a722a1fa93dc60065f6f516db80b06f4ad1".to_string(),
        ]
    );
}

#[test]
fn golden_three_leaf_root() {
    let col = LeafCollection::new(fixed_payloads()).unwrap();
    assert_eq!(hex(&col.root), "7a197bf8d0087983959a2268d05b2145eae7c2713c0ecd07a6b497ccd6f7705b");
}
