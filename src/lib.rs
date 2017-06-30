// The reference algorithm used is from https://github.com/ethereum/wiki/wiki/Ethash

mod miller_rabin;
use miller_rabin::is_prime;

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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
