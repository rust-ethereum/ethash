#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use ethereum_types::{Address, Bloom, H256, H64, U256};
use rlp::{Rlp, RlpStream};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub uncles_hash: H256,
    pub author: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub log_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: H64,
}

impl BlockHeader {
    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream, false);
        let data = stream.out();
        crate::keccak_256(&data).into()
    }

    pub fn seal_hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.stream_rlp(&mut stream, true);
        let data = stream.out();
        crate::keccak_256(&data).into()
    }

    fn stream_rlp(&self, stream: &mut RlpStream, partial: bool) {
        stream.begin_list(13 + if !partial { 2 } else { 0 });
        stream.append(&self.parent_hash);
        stream.append(&self.uncles_hash);
        stream.append(&self.author);
        stream.append(&self.state_root);
        stream.append(&self.transactions_root);
        stream.append(&self.receipts_root);
        stream.append(&self.log_bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data);

        if !partial {
            stream.append(&self.mix_hash);
            stream.append(&self.nonce);
        }
    }
}

impl rlp::Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) { self.stream_rlp(s, false); }
}

impl rlp::Decodable for BlockHeader {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            parent_hash: rlp.val_at(0)?,
            uncles_hash: rlp.val_at(1)?,
            author: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            log_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            mix_hash: rlp.val_at(13)?,
            nonce: rlp.val_at(14)?,
        })
    }
}
