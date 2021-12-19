use alloc::vec::Vec;
use ethereum_types::{H256, H64, U256};

const EPOCH_LENGTH: usize = 30_000;

pub struct LightDAG {
    epoch: usize,
    cache: Vec<u8>,
    #[allow(dead_code)]
    cache_size: usize,
    full_size: usize,
}

impl LightDAG {
    pub fn new(number: U256) -> Self {
        let epoch = (number / EPOCH_LENGTH).as_usize();
        let cache_size = crate::get_cache_size(epoch);
        let full_size = crate::get_full_size(epoch);
        let seed = crate::get_seedhash(epoch);

        let mut cache: Vec<u8> = alloc::vec![0; cache_size];
        crate::make_cache(&mut cache, seed);

        Self {
            cache,
            cache_size,
            full_size,
            epoch,
        }
    }

    pub fn hashimoto(&self, hash: H256, nonce: H64) -> (H256, H256) {
        crate::hashimoto_light(hash, nonce, self.full_size, &self.cache)
    }

    pub fn is_valid_for(&self, number: U256) -> bool {
        (number / EPOCH_LENGTH).as_usize() == self.epoch
    }
}
