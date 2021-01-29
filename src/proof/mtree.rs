use core::convert::TryInto;
use core::ops::Deref;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

use ethereum_types::H256;
use lazy_static::lazy_static;
use sha2::Digest;

const HASH_LENGTH: usize = 16; // bytes.
const WORD_LENGTH: usize = 128; // bytes.
const BRANCH_ELEMENT_LENGTH: usize = 32; // bytes.
const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[&DobuleLeaf] = &[];
const ZERO_HASHES_MAX_INDEX: usize = 48;

lazy_static! {
    /// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
    static ref ZERO_NODES: Vec<MerkleTree<'static>> = {
        (0..=MAX_TREE_DEPTH).map(MerkleTree::Zero).collect()
    };

    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    pub static ref ZERO_HASHES: Vec<Hash> = {
        let mut hashes = vec![Hash::zero(); ZERO_HASHES_MAX_INDEX + 1];

        for i in 0..ZERO_HASHES_MAX_INDEX {
            hashes[i + 1] = super::mtree::hash(&hashes[i], &hashes[i]);
        }
        hashes
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Hash(pub [u8; HASH_LENGTH]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word(pub [u8; WORD_LENGTH]);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) struct BranchElement(pub [u8; BRANCH_ELEMENT_LENGTH]);

impl Hash {
    pub fn zero() -> Self { Self([0u8; HASH_LENGTH]) }
}

impl Word {
    pub fn into_h256_array(mut self) -> [H256; 4] {
        self.0
            .chunks_exact_mut(32)
            .map(|s| {
                s.reverse();
                H256::from_slice(s)
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("hash to H256 should never fails")
    }

    /// #### Conventional encoding
    ///
    /// To make it easier for ethereum smartcontract to follow the hash
    /// calculation, we use a convention to encode DAG dataset element to use in
    /// hash function. The encoding is defined as the following pseudo code:
    ///
    /// - 1 assume the element is `abcd` where a, b, c, d are 32 bytes word
    /// - 2 `first = concat(reverse(a), reverse(b))` where `reverse` reverses
    ///   the bytes.
    /// - 3 `second = concat(reverse(c), reverse(d))`
    /// 4. conventional encoding of `abcd` is `concat(first, second)`
    pub fn conventional(&self) -> ([u8; 64], [u8; 64]) {
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        self.0
            .clone()
            .chunks_exact_mut(32)
            .map(|c| {
                c.reverse();
                c
            })
            .enumerate()
            .for_each(|(i, chunk)| match i {
                0 => first[0..32].copy_from_slice(chunk),
                1 => first[32..64].copy_from_slice(chunk),
                2 => second[0..32].copy_from_slice(chunk),
                3 => second[32..64].copy_from_slice(chunk),
                _ => unreachable!("only 4 chunks"),
            });
        (first, second)
    }
}

impl From<[u8; HASH_LENGTH]> for Hash {
    fn from(b: [u8; HASH_LENGTH]) -> Self { Self(b) }
}

impl<'a> From<&'a [u8]> for Hash {
    fn from(b: &'a [u8]) -> Self {
        assert_eq!(b.len(), HASH_LENGTH);
        let mut inner = [0u8; HASH_LENGTH];
        inner.copy_from_slice(&b);
        Self(inner)
    }
}

impl From<[u8; WORD_LENGTH]> for Word {
    fn from(b: [u8; WORD_LENGTH]) -> Self { Self(b) }
}

impl<'a> From<&'a [u8]> for Word {
    fn from(b: &'a [u8]) -> Self {
        assert_eq!(b.len(), WORD_LENGTH);
        let mut inner = [0u8; WORD_LENGTH];
        inner.copy_from_slice(&b);
        Self(inner)
    }
}

impl From<[u8; BRANCH_ELEMENT_LENGTH]> for BranchElement {
    fn from(b: [u8; BRANCH_ELEMENT_LENGTH]) -> Self { Self(b) }
}

impl From<[Hash; 2]> for BranchElement {
    fn from([h1, h2]: [Hash; 2]) -> Self {
        let mut b: [u8; BRANCH_ELEMENT_LENGTH] = [0; BRANCH_ELEMENT_LENGTH];
        b[0..16].copy_from_slice(h1.deref());
        b[16..32].copy_from_slice(h2.deref());
        Self(b)
    }
}

impl From<[H256; 4]> for Word {
    fn from(b: [H256; 4]) -> Self {
        let mut inner = [0u8; WORD_LENGTH];
        inner[0..32].copy_from_slice(b[0].as_bytes());
        inner[32..64].copy_from_slice(b[1].as_bytes());
        inner[64..96].copy_from_slice(b[2].as_bytes());
        inner[96..128].copy_from_slice(b[3].as_bytes());
        Self(inner)
    }
}

impl Into<[H256; 4]> for Word {
    fn into(self) -> [H256; 4] { self.into_h256_array() }
}

impl Deref for Hash {
    type Target = [u8; HASH_LENGTH];

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Deref for Word {
    type Target = [u8; WORD_LENGTH];

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Deref for BranchElement {
    type Target = [u8; BRANCH_ELEMENT_LENGTH];

    fn deref(&self) -> &Self::Target { &self.0 }
}

pub(super) fn hash(a: &Hash, b: &Hash) -> Hash {
    let hasher = sha2::Sha256::default();
    let hash = hasher
        .chain([0u8; 16])
        .chain(a.0)
        .chain([0u8; 16])
        .chain(b.0)
        .result();
    let mut data = [0u8; HASH_LENGTH];
    data.copy_from_slice(&hash[HASH_LENGTH..]);
    Hash(data)
}

pub(super) fn hash_element(word: &Word) -> Hash {
    let (first, second) = word.conventional();
    let hasher = sha2::Sha256::default();
    let hash = hasher.chain(first).chain(second).result();
    let mut data = [0u8; HASH_LENGTH];
    data.copy_from_slice(&hash[HASH_LENGTH..]);
    Hash(data)
}

/// Right-sparse Merkle tree.
///
/// Efficiently represents a Merkle tree of fixed depth where only the first N
/// indices are populated by non-zero leaves (perfect for the deposit contract
/// tree).
#[derive(Debug, PartialEq)]
pub enum MerkleTree<'a> {
    /// Leaf node with the hash of its content.
    Leaf(&'a DobuleLeaf),
    /// Internal node with hash, left subtree and right subtree.
    Node(Hash, Box<Self>, Box<Self>),
    /// Zero subtree of a given depth.
    ///
    /// It represents a Merkle tree of 2^depth zero leaves.
    Zero(usize),
}

#[derive(Debug, PartialEq, Clone)]
pub enum MerkleTreeError {
    // Trying to push in a leaf
    LeafReached,
    // No more space in the MerkleTree
    MerkleTreeFull,
    // MerkleTree is invalid
    Invalid,
    // Incorrect Depth provided
    DepthTooSmall,
    // Overflow occurred
    ArithError,
}

impl<'a> MerkleTree<'a> {
    /// Create a new Merkle tree from a list of leaves and a fixed depth.
    pub fn create(leaves: &[&'a DobuleLeaf], depth: usize) -> Self {
        use MerkleTree::*;

        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            },
            _ => {
                // Split leaves into left and right subtrees
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) =
                    if leaves.len() <= subtree_capacity {
                        (leaves, EMPTY_SLICE)
                    } else {
                        leaves.split_at(subtree_capacity)
                    };

                let left_subtree = MerkleTree::create(left_leaves, depth - 1);
                let right_subtree = MerkleTree::create(right_leaves, depth - 1);
                let h = hash(&left_subtree.hash(), &right_subtree.hash());

                Node(h, Box::new(left_subtree), Box::new(right_subtree))
            },
        }
    }

    /// Push an element in the MerkleTree.
    /// MerkleTree and depth must be correct, as the algorithm expects valid
    /// data.
    pub fn push_leaf(
        &mut self,
        elem: &'a DobuleLeaf,
        depth: usize,
    ) -> Result<(), MerkleTreeError> {
        use MerkleTree::*;

        if depth == 0 {
            return Err(MerkleTreeError::DepthTooSmall);
        }

        match self {
            Leaf(_) => return Err(MerkleTreeError::LeafReached),
            Zero(_) => {
                *self = MerkleTree::create(&[elem], depth);
            },
            Node(ref mut h, ref mut left, ref mut right) => {
                let left: &mut MerkleTree = &mut *left;
                let right: &mut MerkleTree = &mut *right;
                match (&*left, &*right) {
                    // Tree is full
                    (Leaf(_), Leaf(_)) => {
                        return Err(MerkleTreeError::MerkleTreeFull)
                    },
                    // There is a right node so insert in right node
                    (Node(_, _, _), Node(_, _, _)) => {
                        if let Err(e) = right.push_leaf(elem, depth - 1) {
                            return Err(e);
                        }
                    },
                    // Both branches are zero, insert in left one
                    (Zero(_), Zero(_)) => {
                        *left = MerkleTree::create(&[elem], depth - 1);
                    },
                    // Leaf on left branch and zero on right branch, insert on
                    // right side
                    (Leaf(_), Zero(_)) => {
                        *right = MerkleTree::create(&[elem], depth - 1);
                    },
                    // Try inserting on the left node -> if it fails because it
                    // is full, insert in right side.
                    (Node(_, _, _), Zero(_)) => {
                        match left.push_leaf(elem, depth - 1) {
                            Ok(_) => (),
                            // Left node is full, insert in right node
                            Err(MerkleTreeError::MerkleTreeFull) => {
                                *right = MerkleTree::create(&[elem], depth - 1);
                            },
                            Err(e) => return Err(e),
                        };
                    },
                    // All other possibilities are invalid MerkleTrees
                    (_, _) => return Err(MerkleTreeError::Invalid),
                };
                *h = hash(&left.hash(), &right.hash());
            },
        }

        Ok(())
    }

    /// Retrieve the root hash of this Merkle tree.
    pub fn hash(&self) -> Hash {
        match *self {
            MerkleTree::Leaf(ref h) => h.hash,
            MerkleTree::Node(h, _, _) => h,
            MerkleTree::Zero(depth) => ZERO_HASHES[depth],
        }
    }

    /// Retrieve the value [`Word`] of this Merkle tree (if any).
    pub fn value(&self) -> Option<Word> {
        match *self {
            MerkleTree::Leaf(ref h) => Some(h.word.clone()),
            MerkleTree::Node(_, _, _) => None,
            MerkleTree::Zero(_) => None,
        }
    }

    /// Get a reference to the left and right subtrees if they exist.
    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        match *self {
            MerkleTree::Leaf(_) | MerkleTree::Zero(0) => None,
            MerkleTree::Node(_, ref l, ref r) => Some((l, r)),
            MerkleTree::Zero(depth) => {
                Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1]))
            },
        }
    }

    /// Is this Merkle tree a leaf?
    pub fn is_leaf(&self) -> bool { matches!(self, MerkleTree::Leaf(_)) }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(
        &self,
        index: usize,
        depth: usize,
    ) -> (Word, Hash, Vec<Hash>) {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            // Note: unwrap is safe because leaves are only ever constructed at
            // depth == 0.
            let (left, right) = current_node.left_and_right_branches().unwrap();

            // Go right, include the left branch in the proof.
            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        // Put proof in bottom-up order.
        proof.reverse();

        (current_node.value().unwrap(), current_node.hash(), proof)
    }
}

/// Verify a proof that `element` exists at `index` in a Merkle tree rooted at
/// `root`.
///
/// The `branch` argument is the main component of the proof: it should be a
/// list of internal node hashes such that the root can be reconstructed (in
/// bottom-up order).
pub fn verify_merkle_proof(
    element: &Word,
    branch: &[Hash],
    depth: usize,
    index: usize,
    root: Hash,
) -> bool {
    if branch.len() == depth {
        let leaf = hash_element(element);
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
fn merkle_root_from_branch(
    leaf: Hash,
    branch: &[Hash],
    depth: usize,
    index: usize,
) -> Hash {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut mroot = leaf;

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            mroot = hash(&leaf, &mroot);
        } else {
            mroot = hash(&mroot, &leaf);
        }
    }
    mroot
}

/// Element that holds the actual data and it's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DobuleLeaf {
    pub hash: Hash,
    pub word: Word,
}

impl DobuleLeaf {
    pub fn new(word: Word) -> Self {
        Self {
            hash: hash_element(&word),
            word,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_to_h256_array() {
        let word: [u8; WORD_LENGTH] = [
            1, 2, 3, 4, 5, 6, 7, 8, // 0
            1, 2, 3, 4, 5, 6, 7, 8, // 1
            1, 2, 3, 4, 5, 6, 7, 8, // 2
            1, 2, 3, 4, 5, 6, 7, 8, // 3
            1, 2, 3, 4, 5, 6, 7, 8, // 4
            1, 2, 3, 4, 5, 6, 7, 8, // 5
            1, 2, 3, 4, 5, 6, 7, 8, // 6
            1, 2, 3, 4, 5, 6, 7, 8, // 7
            1, 2, 3, 4, 5, 6, 7, 8, // 8
            1, 2, 3, 4, 5, 6, 7, 8, // 9
            1, 2, 3, 4, 5, 6, 7, 8, // a
            1, 2, 3, 4, 5, 6, 7, 8, // b
            1, 2, 3, 4, 5, 6, 7, 8, // c
            1, 2, 3, 4, 5, 6, 7, 8, // d
            1, 2, 3, 4, 5, 6, 7, 8, // e
            1, 2, 3, 4, 5, 6, 7, 8, // f
        ];
        let _hashes = Word::from(word).into_h256_array();
    }
}
