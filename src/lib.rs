//! Apache-2 licensed Ethash implementation.

// The reference algorithm used is from https://github.com/ethereum/wiki/wiki/Ethash

extern crate sha3;
extern crate rlp;
extern crate bigint;
extern crate byteorder;

mod miller_rabin;

use miller_rabin::is_prime;
use sha3::{Digest, Keccak256, Keccak512};
use bigint::{H1024, U256, H256, H64, H512};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rlp::Encodable;
use std::ops::BitXor;

const DATASET_BYTES_INIT: usize = 1073741824; // 2 to the power of 30.
const DATASET_BYTES_GROWTH: usize = 8388608; // 2 to the power of 23.
const CACHE_BYTES_INIT: usize = 16777216; // 2 to the power of 24.
const CACHE_BYTES_GROWTH: usize = 131072; // 2 to the power of 17.
const CACHE_MULTIPLIER: usize = 1024;
const MIX_BYTES: usize = 128;
const WORD_BYTES: usize = 4;
const HASH_BYTES: usize = 64;
const DATASET_PARENTS: usize = 256;
const CACHE_ROUNDS: usize = 3;
const ACCESSES: usize = 64;

pub const EPOCH_LENGTH: usize = 30000;

pub fn get_cache_size(block_number: U256) -> usize {
    let block_number = block_number.as_usize();

    let mut sz = CACHE_BYTES_INIT + CACHE_BYTES_GROWTH * (block_number / EPOCH_LENGTH);
    sz -= HASH_BYTES;
    while !is_prime(sz / HASH_BYTES) {
        sz -= 2 * HASH_BYTES;
    }
    sz
}

pub fn get_full_size(block_number: U256) -> usize {
    let block_number = block_number.as_usize();

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

/// Make an Ethash cache using the given seed.
pub fn make_cache(cache: &mut [u8], seed: H256) {
    assert!(cache.len() % HASH_BYTES == 0);
    let n = cache.len() / HASH_BYTES;

    fill_sha512(&seed, cache, 0);

    for i in 1..n {
        let (last, next) = cache.split_at_mut(i * 64);
        fill_sha512(&last[(last.len()-64)..], next, 0);
    }

    for _ in 0..CACHE_ROUNDS {
        for i in 0..n {
            let v = ((&cache[(i * 64)..]).read_u32::<LittleEndian>().unwrap() as usize) % n;

            let mut r = [0u8; 64];
            for j in 0..64 {
                let a = cache[((n + i - 1) % n) * 64 + j];
                let b = cache[v * 64 + j];
                r[j] = a.bitxor(b);
            }
            fill_sha512(&r, cache, i * 64);
        }
    }
}

const FNV_PRIME: u32 = 0x01000193;
fn fnv(v1: u32, v2: u32) -> u32 {
    let v1 = v1 as u64;
    let v2 = v2 as u64;

    ((((v1 * 0x01000000 | 0) + (v1 * 0x193 | 0)) ^ v2) >> 0) as u32
}

fn fnv64(a: [u8; 64], b: [u8; 64]) -> [u8; 64] {
    let mut r = [0u8; 64];
    for i in 0..(64 / 4) {
        let j = i * 4;
        let a32 = (&a[j..]).read_u32::<LittleEndian>().unwrap();
        let b32 = (&b[j..]).read_u32::<LittleEndian>().unwrap();

        (&mut r[j..]).write_u32::<LittleEndian>(
            fnv((&a[j..]).read_u32::<LittleEndian>().unwrap(),
                (&b[j..]).read_u32::<LittleEndian>().unwrap()));
    }
    r
}

fn fnv128(a: [u8; 128], b: [u8; 128]) -> [u8; 128] {
    let mut r = [0u8; 128];
    for i in 0..(128 / 4) {
        let j = i * 4;
        let a32 = (&a[j..]).read_u32::<LittleEndian>().unwrap();
        let b32 = (&b[j..]).read_u32::<LittleEndian>().unwrap();

        (&mut r[j..]).write_u32::<LittleEndian>(
            fnv((&a[j..]).read_u32::<LittleEndian>().unwrap(),
                (&b[j..]).read_u32::<LittleEndian>().unwrap()));
    }
    r
}

fn u8s_to_u32(a: &[u8]) -> u32 {
    let n = a.len();
    (a[0] as u32) + (a[1] as u32) << 8 +
        (a[2] as u32) << 16 + (a[3] as u32) << 24
}

pub fn calc_dataset_item(cache: &[u8], i: usize) -> H512 {
    debug_assert!(cache.len() % 64 == 0);

    let n = cache.len() / 64;
    let r = HASH_BYTES / WORD_BYTES;
    let mut mix = [0u8; 64];
    for j in 0..64 {
        mix[j] = cache[(i % n) * 64 + j];
    }
    let mix_first32 = mix.as_ref().read_u32::<LittleEndian>().unwrap().bitxor(i as u32);
    mix.as_mut().write_u32::<LittleEndian>(mix_first32);
    {
        let mut remix = [0u8; 64];
        for j in 0..64 {
            remix[j] = mix[j];
        }
        fill_sha512(&remix, &mut mix, 0);
    }
    for j in 0..DATASET_PARENTS {
        let cache_index = fnv((i.bitxor(j) & (u32::max_value() as usize)) as u32,
                              (&mix[(j % r * 4)..]).read_u32::<LittleEndian>().unwrap()) as usize;
        let mut item = [0u8; 64];
        let cache_index = cache_index % n;
        for i in 0..64 {
            item[i] = cache[cache_index * 64 + i];
        }
        mix = fnv64(mix, item);
    }
    let mut z = [0u8; 64];
    fill_sha512(&mix, &mut z, 0);
    H512::from(z)
}

/// Make an Ethash dataset using the given hash.
pub fn make_dataset(dataset: &mut [u8], cache: &[u8]) {
    let n = dataset.len() / HASH_BYTES;
    for i in 0..n {
        let z = calc_dataset_item(cache, i);
        for j in 0..64 {
            dataset[i * 64 + j] = z[j];
        }
    }
}

/// "Main" function of Ethash, calculating the mix digest and result given the
/// header and nonce.
pub fn hashimoto<F: Fn(usize) -> H512>(
    header_hash: H256, nonce: H64, full_size: usize, lookup: F
) -> (H256, H256) {
    let n = full_size / HASH_BYTES;
    let w = MIX_BYTES / WORD_BYTES;
    const MIXHASHES: usize = MIX_BYTES / HASH_BYTES;
    let s = {
        let mut hasher = Keccak512::default();
        let mut reversed_nonce: Vec<u8> = nonce.as_ref().into();
        reversed_nonce.reverse();
        hasher.input(&header_hash);
        hasher.input(&reversed_nonce);
        hasher.result()
    };
    let mut mix = [0u8; MIX_BYTES];
    for i in 0..MIXHASHES {
        for j in 0..64 {
            mix[i * HASH_BYTES + j] = s[j];
        }
    }

    for i in 0..ACCESSES {
        let p = (fnv((i as u32).bitxor(s.as_ref().read_u32::<LittleEndian>().unwrap()),
                     (&mix[(i % w * 4)..]).read_u32::<LittleEndian>().unwrap())
                 as usize) % (n / MIXHASHES) * MIXHASHES;
        let mut newdata = [0u8; MIX_BYTES];
        for j in 0..MIXHASHES {
            let v = lookup(p + j);
            for k in 0..64 {
                newdata[j * 64 + k] = v[k];
            }
        }
        mix = fnv128(mix, newdata);
    }
    let mut cmix = [0u8; MIX_BYTES / 4];
    for i in 0..(MIX_BYTES / 4 / 4) {
        let j = i * 4;
        let a = fnv((&mix[(j * 4)..]).read_u32::<LittleEndian>().unwrap(),
                    (&mix[((j + 1) * 4)..]).read_u32::<LittleEndian>().unwrap());
        let b = fnv(a, (&mix[((j + 2) * 4)..]).read_u32::<LittleEndian>().unwrap());
        let c = fnv(b, (&mix[((j + 3) * 4)..]).read_u32::<LittleEndian>().unwrap());

        (&mut cmix[j..]).write_u32::<LittleEndian>(c);
    }
    let result = {
        let mut hasher = Keccak256::default();
        hasher.input(&s);
        hasher.input(&cmix);
        let r = hasher.result();
        let mut z = [0u8; 32];
        for i in 0..32 {
            z[i] = r[i];
        }
        z
    };
    (H256::from(cmix), H256::from(result))
}

/// Ethash used by a light client. Only stores the 16MB cache rather than the
/// full dataset.
pub fn hashimoto_light<T: Encodable>(
    header: &T, nonce: H64, full_size: usize, cache: &[u8]
) -> (H256, H256) {
    let header = rlp::encode(header).to_vec();

    hashimoto(H256::from(Keccak256::digest(&header).as_slice()), nonce, full_size, |i| {
        calc_dataset_item(cache, i)
    })
}

/// Ethash used by a full client. Stores the whole dataset in memory.
pub fn hashimoto_full<T: Encodable>(
    header: &T, nonce: H64, full_size: usize, dataset: &[u8]
) -> (H256, H256) {
    let header = rlp::encode(header).to_vec();

    hashimoto(H256::from(Keccak256::digest(&header).as_slice()), nonce, full_size, |i| {
        let mut r = [0u8; 64];
        for j in 0..64 {
            r[j] = dataset[i * 64 + j];
        }
        H512::from(r)
    })
}

/// Mine a nonce given the header, dataset, and the target. Target is derived
/// from the difficulty.
pub fn mine<T: Encodable>(
    header: &T, full_size: usize, dataset: &[u8], nonce_start: H64, difficulty: U256
) -> (H64, H256) {
    let target = U256::max_value() / difficulty;
    let header = rlp::encode(header).to_vec();

    let mut nonce_current = nonce_start;
    loop {
        let (_, result) = hashimoto(H256::from(Keccak256::digest(&header).as_slice()), nonce_current, full_size, |i| {
            let mut r = [0u8; 64];
            for j in 0..64 {
                r[j] = dataset[i * 64 + j];
            }
            H512::from(r)
        });
        let result_cmp: U256 = result.into();
        if result_cmp <= target {
            return (nonce_current, result);
        }
        let nonce_u64: u64 = nonce_current.into();
        nonce_current = H64::from(nonce_u64 + 1);
    }
}

/// Get the seedhash for a given block number.
pub fn get_seedhash(block_number: U256) -> H256 {
    let block_number = block_number.as_usize();

    let mut s = [0u8; 32];
    if block_number != 0 {
        for i in 0..(block_number / EPOCH_LENGTH) {
            fill_sha256(&s.clone(), &mut s, 0);
        }
    }
    H256::from(s.as_ref())
}
