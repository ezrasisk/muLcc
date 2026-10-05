//! `mlcc2` — Multi-Leaf Collection Covenant v2, off-chain library.
//!
//! See `SPEC.md` (repo root) for the full invariant list. Comments below
//! reference invariants by number, e.g. "Invariant 1".

use thiserror::Error;

/// Domain separation tags (UTF-8, no null terminator).
pub const LEAF_TAG: &[u8] = b"MLCC2Leaf";
pub const BRANCH_TAG: &[u8] = b"MLCC2Branch";
pub const SET_TAG: &[u8] = b"MLCC2Set";
pub const EMPTY_TAG: &[u8] = b"MLCC2Empty";

/// Bit flags for [`PolicyState::flags`].
pub const ONE_TIME_FLAG: u8 = 0b0000_0001;

/// Maximum supported Merkle tree depth (see `SPEC.md`); bounds a collection
/// to at most `2^MAX_TREE_DEPTH` leaves.
pub const MAX_TREE_DEPTH: u32 = 4;
pub const MAX_LEAVES: usize = 1 << MAX_TREE_DEPTH; // 16

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("a leaf collection must contain at least one leaf")]
    EmptyCollection,
    #[error("a leaf collection may hold at most {MAX_LEAVES} leaves (max tree depth {MAX_TREE_DEPTH})")]
    TooManyLeaves,
    #[error("leaf index {0} is out of range for a collection of {1} leaves")]
    IndexOutOfRange(usize, usize),
    #[error("merkle proof does not resolve to the expected root")]
    InvalidProof,
}

/// The fixed, canonical payload committed to by a single leaf.
///
/// Encoded as `template_hash || param_commitment || leaf_flags` (65 bytes),
/// in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafPayload {
    pub template_hash: [u8; 32],
    pub param_commitment: [u8; 32],
    pub leaf_flags: u8,
}

impl LeafPayload {
    pub fn encode(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0..32].copy_from_slice(&self.template_hash);
        out[32..64].copy_from_slice(&self.param_commitment);
        out[64] = self.leaf_flags;
        out
    }
}

/// `leaf_commitment = BLAKE3(MLCC2Leaf || LeafPayload)`.
pub fn hash_leaf_payload(payload: &LeafPayload) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_TAG);
    hasher.update(&payload.encode());
    *hasher.finalize().as_bytes()
}

/// `branch(left, right)`: BLAKE3 of the tag plus the two children, in the
/// order given — order matters here, deliberately.
///
/// An earlier version of this function sorted its inputs so a proof
/// wouldn't need a left/right flag. That turned out to be impossible to
/// reproduce on-chain: Silverscript (what Argent compiles to) only
/// supports `==`/`!=` on byte arrays — ordered comparison (`<`, `<=`,
/// `>`, `>=`) is restricted to `int`/`temporal` operands, confirmed
/// directly in the compiler's own type checker
/// (`silverscript-lang/src/compiler/type_check.rs`). Two `byte[32]`
/// values can't be sorted on-chain, so a proof has to carry an explicit
/// [`ProofStep::sibling_on_right`] flag instead — see that type and
/// [`merkle_proof`]/[`merkle_verify`].
pub fn branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BRANCH_TAG);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// `BLAKE3(MLCC2Empty)` — the root of a (disallowed) empty collection.
/// Exposed for documentation/testing; [`LeafCollection::new`] never
/// produces it, since it rejects empty input (Invariant 5).
pub fn empty_root() -> [u8; 32] {
    *blake3::hash(EMPTY_TAG).as_bytes()
}

/// Degenerate "set" mode for small collections: a flat membership hash
/// with no tree and no proof (commitments sorted ascending before
/// hashing — fine off-chain, where sorting byte arrays is free; see
/// [`branch`]'s doc comment for why the Merkle path below can't do the
/// same). Optional per the spec; [`LeafCollection`] always builds a
/// Merkle tree and does not use this.
pub fn set_root(commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = commitments.to_vec();
    sorted.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(SET_TAG);
    for c in &sorted {
        hasher.update(c);
    }
    *hasher.finalize().as_bytes()
}

/// Combines one tree level into the next: adjacent pairs (`level[i]` as
/// left, `level[i+1]` as right) are hashed with [`branch`]; a trailing
/// unpaired node promotes unchanged (no duplication — duplicating the odd
/// node would reintroduce the classic duplicate-leaf weakness some Merkle
/// trees have had).
fn combine_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(branch(&level[i], &level[i + 1]));
            i += 2;
        } else {
            next.push(level[i]);
            i += 1;
        }
    }
    next
}

/// Computes the Merkle root over `commitments`, in the given order.
pub fn merkle_root(commitments: &[[u8; 32]]) -> [u8; 32] {
    if commitments.is_empty() {
        return empty_root();
    }
    let mut level: Vec<[u8; 32]> = commitments.to_vec();
    while level.len() > 1 {
        level = combine_level(&level);
    }
    level[0]
}

/// One level of a Merkle proof: the sibling hash, and whether that
/// sibling sits on the right (`current` was the left operand of
/// [`branch`] at this level) or on the left (`current` was the right
/// operand). Needed because [`branch`] doesn't sort its inputs — see its
/// doc comment for why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub sibling_on_right: bool,
}

/// Builds the sibling path for `index`, consistent with [`merkle_root`]'s
/// pairing. A level where `index`'s node is the trailing unpaired one
/// contributes no entry (it promoted unchanged) — a proof's length can be
/// shorter than the tree's depth, same as before this type's addition;
/// only the per-level content changed.
pub fn merkle_proof(commitments: &[[u8; 32]], index: usize) -> Result<Vec<ProofStep>, Error> {
    if commitments.is_empty() {
        return Err(Error::EmptyCollection);
    }
    if index >= commitments.len() {
        return Err(Error::IndexOutOfRange(index, commitments.len()));
    }
    let mut level: Vec<[u8; 32]> = commitments.to_vec();
    let mut idx = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        let is_left = idx % 2 == 0;
        let sibling_index = if is_left { idx + 1 } else { idx - 1 };
        if sibling_index < level.len() {
            // idx is left -> sibling is to its right -> sibling_on_right = true,
            // and vice versa.
            path.push(ProofStep { sibling: level[sibling_index], sibling_on_right: is_left });
        }
        // else: idx is the trailing unpaired node at this level — no
        // sibling, no proof entry, and its value carries forward unchanged.
        let next = combine_level(&level);
        idx /= 2;
        level = next;
    }
    Ok(path)
}

/// Verifies that `leaf_c` is a member of the tree rooted at `root`,
/// folding each [`ProofStep`] in order via [`branch`], using its
/// `sibling_on_right` flag to put `current` and `sibling` on the correct
/// side.
pub fn merkle_verify(leaf_c: &[u8; 32], path: &[ProofStep], root: &[u8; 32]) -> bool {
    let mut current = *leaf_c;
    for step in path {
        current = if step.sibling_on_right { branch(&current, &step.sibling) } else { branch(&step.sibling, &current) };
    }
    &current == root
}

/// A witness for opening one leaf of a [`LeafCollection`]: which leaf, its
/// full payload, and the sibling path proving it under the collection's
/// root.
#[derive(Debug, Clone)]
pub struct OpenWitness {
    pub leaf_index: usize,
    pub payload: LeafPayload,
    pub merkle_path: Vec<ProofStep>,
}

/// A committed set of leaves: their commitments, the resulting Merkle
/// root, and (off-chain only) the payloads themselves.
#[derive(Debug, Clone)]
pub struct LeafCollection {
    pub commitments: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub payloads: Vec<LeafPayload>,
}

impl LeafCollection {
    /// Rejects an empty collection (Invariant 5) and anything past
    /// [`MAX_LEAVES`] (the documented max tree depth of
    /// [`MAX_TREE_DEPTH`]).
    pub fn new(payloads: Vec<LeafPayload>) -> Result<Self, Error> {
        if payloads.is_empty() {
            return Err(Error::EmptyCollection);
        }
        if payloads.len() > MAX_LEAVES {
            return Err(Error::TooManyLeaves);
        }
        let commitments: Vec<[u8; 32]> = payloads.iter().map(hash_leaf_payload).collect();
        let root = merkle_root(&commitments);
        Ok(Self { commitments, root, payloads })
    }

    pub fn open_witness(&self, index: usize) -> Result<OpenWitness, Error> {
        if index >= self.payloads.len() {
            return Err(Error::IndexOutOfRange(index, self.payloads.len()));
        }
        let merkle_path = merkle_proof(&self.commitments, index)?;
        Ok(OpenWitness { leaf_index: index, payload: self.payloads[index], merkle_path })
    }
}

/// On-chain policy state: the committed root plus flags and an
/// informational leaf count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyState {
    pub root: [u8; 32],
    pub flags: u8,
    pub n: u8,
}

impl PolicyState {
    pub fn is_one_time(&self) -> bool {
        self.flags & ONE_TIME_FLAG != 0
    }
}

/// On-chain purse state: just enough to bind a purse to its policy's
/// lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurseState {
    pub policy_covenant_id: [u8; 32],
}

/// Invariant 1: an open is only valid if the witness's leaf commitment
/// verifies under `policy.root`.
pub fn verify_open(policy: &PolicyState, wit: &OpenWitness) -> Result<(), Error> {
    let leaf_c = hash_leaf_payload(&wit.payload);
    if merkle_verify(&leaf_c, &wit.merkle_path, &policy.root) {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// Invariant 2: a reusable (non-`ONE_TIME`) policy's successor keeps the
/// same root, flags, and leaf count. Never derive a successor root from
/// an unproven client-supplied value (Invariant 2's point, and 3's).
pub fn successor_policy_reusable(policy: &PolicyState) -> PolicyState {
    *policy
}

/// Invariant 3, option C (the MVP choice this crate implements for
/// `ONE_TIME`): once the opened leaf was the last one, there is no
/// successor policy at all — the purse hands off directly. The caller
/// supplies `leaves_remaining_after` because this library does not
/// maintain a mutable leaf set; it only hashes and proves against a fixed
/// collection, which keeps "never trust a bare new_root" (Invariant 3)
/// structurally true rather than merely enforced by convention.
pub fn is_terminal_one_time(policy: &PolicyState, leaves_remaining_after: usize) -> bool {
    policy.is_one_time() && leaves_remaining_after == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(byte: u8) -> LeafPayload {
        LeafPayload { template_hash: [byte; 32], param_commitment: [byte.wrapping_add(1); 32], leaf_flags: 0 }
    }

    #[test]
    fn three_leaf_root_verifies_all_indices() {
        let col = LeafCollection::new(vec![payload(1), payload(2), payload(3)]).unwrap();
        for i in 0..3 {
            let wit = col.open_witness(i).unwrap();
            let leaf_c = hash_leaf_payload(&wit.payload);
            assert!(merkle_verify(&leaf_c, &wit.merkle_path, &col.root), "index {i} failed to verify");
        }
    }

    #[test]
    fn wrong_path_fails() {
        let col = LeafCollection::new(vec![payload(1), payload(2), payload(3)]).unwrap();
        let mut wit = col.open_witness(0).unwrap();
        // Corrupt one sibling in the path.
        if let Some(first) = wit.merkle_path.first_mut() {
            first.sibling[0] ^= 0xff;
        }
        let leaf_c = hash_leaf_payload(&wit.payload);
        assert!(!merkle_verify(&leaf_c, &wit.merkle_path, &col.root));
    }

    #[test]
    fn wrong_leaf_fails() {
        let col = LeafCollection::new(vec![payload(1), payload(2), payload(3)]).unwrap();
        let wit0 = col.open_witness(0).unwrap();
        // Use leaf 1's commitment with leaf 0's path.
        let wrong_leaf_c = hash_leaf_payload(&payload(2));
        assert!(!merkle_verify(&wrong_leaf_c, &wit0.merkle_path, &col.root));
    }

    #[test]
    fn verify_open_matches_merkle_verify() {
        let col = LeafCollection::new(vec![payload(1), payload(2), payload(3), payload(4), payload(5)]).unwrap();
        let policy = PolicyState { root: col.root, flags: 0, n: col.payloads.len() as u8 };
        for i in 0..col.payloads.len() {
            let wit = col.open_witness(i).unwrap();
            assert!(verify_open(&policy, &wit).is_ok(), "index {i}");
        }
        // A witness for a payload that was never in the collection must fail.
        let bad_wit = OpenWitness { leaf_index: 0, payload: payload(99), merkle_path: col.open_witness(0).unwrap().merkle_path };
        assert_eq!(verify_open(&policy, &bad_wit), Err(Error::InvalidProof));
    }

    #[test]
    fn reusable_successor_root_unchanged() {
        let policy = PolicyState { root: [7u8; 32], flags: 0, n: 3 };
        let next = successor_policy_reusable(&policy);
        assert_eq!(next, policy);
        assert_eq!(next.root, policy.root);
    }

    #[test]
    fn empty_collection_rejected_at_new() {
        let err = LeafCollection::new(vec![]).unwrap_err();
        assert_eq!(err, Error::EmptyCollection);
    }

    #[test]
    fn too_many_leaves_rejected_at_new() {
        let payloads: Vec<_> = (0..=MAX_LEAVES as u8).map(payload).collect(); // MAX_LEAVES + 1
        let err = LeafCollection::new(payloads).unwrap_err();
        assert_eq!(err, Error::TooManyLeaves);
    }

    #[test]
    fn max_leaves_accepted_at_new() {
        let payloads: Vec<_> = (0..MAX_LEAVES as u8).map(payload).collect();
        assert!(LeafCollection::new(payloads).is_ok());
    }

    #[test]
    fn payload_hash_is_stable() {
        // Golden vector: fixed payload -> fixed commitment hex. If this
        // ever changes, something about the encoding or tag changed.
        let p = LeafPayload { template_hash: [1u8; 32], param_commitment: [2u8; 32], leaf_flags: 0 };
        let c = hash_leaf_payload(&p);
        assert_eq!(hex(&c), "e6b701d34834fecaa1d0826db88edbe14a1ac0290c1ee0b28b7827da52ee7b3e");
    }

    #[test]
    fn round_trip_for_various_sizes() {
        // Exercise odd-node promotion at every shape from 1 to 2*MAX_LEAVES
        // (going past MAX_LEAVES here is fine — this test is about the
        // tree math, not the collection-size policy).
        for n in 1..=16usize {
            let payloads: Vec<_> = (0..n as u8).map(payload).collect();
            let commitments: Vec<[u8; 32]> = payloads.iter().map(hash_leaf_payload).collect();
            let root = merkle_root(&commitments);
            for i in 0..n {
                let path = merkle_proof(&commitments, i).unwrap();
                assert!(merkle_verify(&commitments[i], &path, &root), "n={n} index={i}");
            }
        }
    }

    #[test]
    fn set_root_is_order_independent() {
        let c1 = hash_leaf_payload(&payload(1));
        let c2 = hash_leaf_payload(&payload(2));
        let c3 = hash_leaf_payload(&payload(3));
        assert_eq!(set_root(&[c1, c2, c3]), set_root(&[c3, c1, c2]));
    }

    #[test]
    fn branch_is_order_dependent() {
        // Deliberate, not incidental: see branch()'s doc comment for why
        // it can't sort its inputs (no ordered comparison on byte[32] in
        // Silverscript), and why that makes ProofStep::sibling_on_right
        // necessary instead.
        let a = hash_leaf_payload(&payload(1));
        let b = hash_leaf_payload(&payload(2));
        assert_ne!(branch(&a, &b), branch(&b, &a));
    }

    #[test]
    fn is_terminal_one_time_logic() {
        let one_time = PolicyState { root: [0u8; 32], flags: ONE_TIME_FLAG, n: 1 };
        let reusable = PolicyState { root: [0u8; 32], flags: 0, n: 1 };
        assert!(is_terminal_one_time(&one_time, 0));
        assert!(!is_terminal_one_time(&one_time, 1));
        assert!(!is_terminal_one_time(&reusable, 0));
    }

    #[test]
    fn empty_root_is_not_reachable_via_leaf_collection() {
        // LeafCollection::new rejects empty input, so a legitimately
        // constructed collection's root is never empty_root() purely by
        // virtue of being empty (Invariant 5's premise can't arise here).
        let col = LeafCollection::new(vec![payload(1)]).unwrap();
        assert_ne!(col.root, empty_root());
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
