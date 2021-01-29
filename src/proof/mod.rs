#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use ethereum_types::{H128, H256, H64};
use tiny_keccak::{Hasher, Keccak};

use crate::ACCESSES;
use crate::MIX_BYTES;

pub const CACHE_LEVEL: u64 = 15;
pub const HASH_LENGTH: usize = 16;
pub const WORD_LENGTH: usize = 128;
pub const BRANCH_ELEMENT_LENGTH: usize = 32;

pub mod mtree;
pub mod types;

pub fn keccak_512(data: &[u8]) -> [u8; 64] {
    let mut keccak = Keccak::v512();
    keccak.update(data);
    let mut output = [0u8; 64];
    keccak.finalize(&mut output);
    output
}

pub fn keccak_256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output
}

pub fn get_indices<F>(
    header_hash: H256,
    nonce: H64,
    full_size: usize,
    lookup: F,
) -> Vec<u32>
where
    F: Fn(usize) -> [u32; HASH_LENGTH],
{
    let mut result = Vec::new();
    let rows = (full_size / MIX_BYTES) as u32;
    let mut seed = [0u8; 40]; // 32 + 8
    seed[0..32].copy_from_slice(header_hash.as_bytes()); // 32
    seed[32..].copy_from_slice(nonce.as_bytes()); // 8
    seed[32..].reverse();
    let seed = keccak_512(&seed);
    let seed_head = LittleEndian::read_u32(&seed);

    const MIX_LEN: usize = MIX_BYTES / 4;
    let mut mix = [0u32; MIX_LEN];
    for (i, b) in mix.iter_mut().enumerate() {
        *b = LittleEndian::read_u32(&seed[(i % 16 * 4)..]);
    }
    let mut temp = [0u32; MIX_LEN];
    for i in 0..ACCESSES {
        let a = i as u32 ^ seed_head;
        let m = mix[i % MIX_LEN];
        let parent = crate::fnv(a, m) % rows;
        result.push(parent);
        for k in 0..MIX_BYTES / ACCESSES {
            let cache_index = 2 * parent + k as u32;
            let data = lookup(cache_index as _);
            let from = k * HASH_LENGTH;
            let to = from + HASH_LENGTH;
            temp[from..to].copy_from_slice(&data);
        }
        crate::fnv_mix_hash(&mut mix, temp);
    }
    result
}

/// A conventional way for calculating the Root hash of the merkle tree.
pub fn calc_dataset_merkle_root(epoch: usize, dataset: &[u8]) -> H128 {
    let (depth, leaves) = calc_dataset_merkle_leaves(epoch, dataset);
    let leaves: Vec<&mtree::DobuleLeaf> = leaves.iter().collect();
    let tree = mtree::MerkleTree::create(&leaves, depth);
    let root = tree.hash();
    H128::from_slice(&root.0)
}

pub fn calc_dataset_depth(epoch: usize) -> usize {
    let full_size = crate::get_full_size(epoch);
    let full_size_128_resolution = full_size / 128;
    format!("{:b}", full_size_128_resolution - 1).len()
}

/// Calculate the merkle tree and return a HashCache that can be used to
/// calculating proofs and can be used to cache them to filesystem.
pub fn calc_dataset_merkle_leaves(
    epoch: usize,
    dataset: &[u8],
) -> (usize, Vec<mtree::DobuleLeaf>) {
    let branch_depth = calc_dataset_depth(epoch);
    let leaves = dataset_leaves(epoch, dataset);
    (branch_depth, leaves)
}

#[cfg(not(feature = "std"))]
fn dataset_leaves(epoch: usize, dataset: &[u8]) -> Vec<mtree::DobuleLeaf> {
    let full_size = crate::get_full_size(epoch);
    let full_size_128_resolution = full_size / 128;
    let mut leaves = Vec::with_capacity(full_size_128_resolution);
    let chunks = dataset.chunks_exact(128);
    for chunk in chunks {
        let mut buf = [0u8; 128];
        buf.copy_from_slice(chunk);
        let word = mtree::Word(buf);
        let leaf = mtree::DobuleLeaf::new(word);
        leaves.push(leaf);
    }
    leaves
}

#[cfg(feature = "std")]
fn dataset_leaves(epoch: usize, dataset: &[u8]) -> Vec<mtree::DobuleLeaf> {
    use rayon::prelude::*;
    let _ = epoch;
    // setup rayon thread pool.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
        .is_ok();

    let leaves = dataset
        .par_chunks_exact(128)
        .map(|chunk| {
            let mut buf = [0u8; 128];
            buf.copy_from_slice(chunk);
            let word = mtree::Word(buf);
            mtree::DobuleLeaf::new(word)
        })
        .collect();
    leaves
}
