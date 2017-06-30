// The reference algorithm used is from https://github.com/ethereum/wiki/wiki/Ethash

extern crate sha3;

mod miller_rabin;
use miller_rabin::is_prime;
use sha3::{Digest, Keccak256, Keccak512};
use std::ops::BitXor;

const WORD_BYTES: usize = 4;
const DATASET_BYTES_INIT: usize = 1073741824; // 2 to the power of 30.
const DATASET_BYTES_GROWTH: usize = 8388608; // 2 to the power of 23.
const CACHE_BYTES_INIT: usize = 16777216; // 2 to the power of 24.
const CACHE_BYTES_GROWTH: usize = 131072; // 2 to the power of 17.
const CACHE_MULTIPLIER: usize = 1024;
const EPOCH_LENGTH: usize = 30000;
const MIX_BYTES: usize = 128;
const HASH_BYTES: usize = 64;
const DATASET_PARENTS: usize = 256;
const CACHE_ROUNDS: usize = 3;
const ACCESSES: usize = 64;

fn get_cache_size(block_number: usize) -> usize {
    let mut sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number / EPOCH_LENGTH);
    sz -= HASH_BYTES;
    while !is_prime(sz / HASH_BYTES) {
        sz -= 2 * HASH_BYTES;
    }
    sz
}

fn get_full_size(block_number: usize) -> usize {
    let mut sz = DATASET_BYTES_INIT + DATASET_BYTES_GROWTH * (block_number / EPOCH_LENGTH);
    sz -= MIX_BYTES;
    while !is_prime(sz / MIX_BYTES) {
        sz -= 2 * MIX_BYTES
    }
    sz
}

fn fill_sha512(input: &[u8], a: &mut [u8], from_index: usize) {
    let mut hasher = Keccak512::default();
    hasher.input(input);
    let out = hasher.result();
    for i in 0..out.len() {
        a[from_index + i] = out[i];
    }
}

fn fill_sha256(input: &[u8], a: &mut [u8], from_index: usize) {
    let mut hasher = Keccak256::default();
    hasher.input(input);
    let out = hasher.result();
    for i in 0..out.len() {
        a[from_index + i] = out[i];
    }
}

pub fn make_cache(cache: &mut [u8], seed: [u8; 64]) {
    let n = cache.len() / HASH_BYTES;
    fill_sha512(&seed, cache, 0);
    for i in 1..n {
        let (last, next) = cache.split_at_mut(i * 64);
        fill_sha512(last, next, 0);
    }
    for _ in 0..CACHE_ROUNDS {
        for i in 0..n {
            let v = (cache[i * 64] as usize) % n;
            let mut r = [0u8; 64];
            for j in 0..64 {
                let a = cache[((i - 1 + n) % n) * 64 + j];
                let b = cache[v * 64 + j];
                r[j] = a.bitxor(b);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
