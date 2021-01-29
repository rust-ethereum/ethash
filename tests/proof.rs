use byteorder::ByteOrder;
use ethash::mtree::{Hash, Word};
use ethash::types;
use ethereum_types::H256;

// this test is used as a playground
#[test]
fn proofs() {
    let rlp_encoded_str = include_str!("fixtures/2.rlp");
    let rlp_encoded = hex::decode(rlp_encoded_str.trim()).unwrap();
    let header: types::BlockHeader = rlp::decode(&rlp_encoded).unwrap();
    let header_hash = header.seal_hash();
    assert_eq!(
        header_hash.as_bytes(),
        hex::decode(
            "d9a38e294d953b1e735e8e71025a1855ed7f2139e13ff8a19bb7e82383576c47"
        )
        .unwrap()
    );

    let dag = ethash::LightDAG::<ethash::EthereumPatch>::new(header.number);
    let (mix_hash, result) = dag.hashimoto(header_hash, header.nonce);
    assert_eq!(
        result.as_bytes(),
        hex::decode(
            "000000003a0a4fb7f886bad18226a47fb09767ac8c0c87141083443ac5cfdf59"
        )
        .unwrap()
    );
    assert_eq!(mix_hash, header.mix_hash);

    let indices =
        ethash::get_indices(header_hash, header.nonce, dag.full_size, |i| {
            let raw_data = ethash::calc_dataset_item(&dag.cache, i);
            let mut data = [0u32; 16];
            for (i, b) in data.iter_mut().enumerate() {
                *b = byteorder::LE::read_u32(&raw_data[(i * 4)..]);
            }
            data
        });

    assert_eq!(
        indices,
        &[
            4990688, 6987316, 1807929, 2596874, 3359925, 3073025, 3519380,
            5337872, 2175509, 4172374, 1572107, 5437761, 4861897, 5627685,
            4991962, 2554186, 3290547, 6561417, 7089885, 7073632, 786997,
            3378685, 6185265, 5283049, 4273209, 3161257, 5030708, 5274872,
            3725170, 202134, 5492399, 6895738, 5696426, 6626457, 2345861,
            262304, 2658959, 7286807, 547777, 5472769, 7664032, 1035384,
            2671289, 4103686, 8347077, 2322872, 6754122, 2654051, 4610695,
            65291, 3601125, 1821797, 5122957, 5336515, 7610054, 652865, 375080,
            5367006, 2543741, 2475727, 341558, 5858560, 7361407, 3569253
        ]
    );
    let dataset_path = std::path::PathBuf::from("target/dataset.bin");
    let dataset = if dataset_path.exists() {
        eprintln!("Dataset found at target/dataset.bin");
        std::fs::read("target/dataset.bin").expect("dataset is generated")
    } else {
        let full_size = ethash::get_full_size(dag.epoch);
        let mut bytes = vec![0u8; full_size];
        eprintln!("Generating dataset ...");
        let now = std::time::Instant::now();
        ethash::make_dataset(&mut bytes, &dag.cache);
        let e = now.elapsed();
        println!("Generated Dataset in {}", humantime::format_duration(e));
        std::fs::write("target/dataset.bin", &bytes).unwrap();
        eprintln!("Dataset is ready!");
        bytes
    };
    let (depth, leaves) =
        ethash::calc_dataset_merkle_leaves(dag.epoch, &dataset);
    let leaves: Vec<_> = leaves.iter().collect();
    let tree = ethash::mtree::MerkleTree::create(&leaves, depth);
    let root = tree.hash();

    // an easier way to calclute the root, if you don't need the proofs.
    // let root = ethash::calc_dataset_merkle_root(dag.epoch, &dataset);
    println!("root: 0x{}", hex::encode(&root.0));
    assert_eq!(hex::encode(root.0), "f346b91a0469b7960a7b00d7812a5023");

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BlockWithProofs {
        pub proof_length: u64,
        pub header_rlp: String,
        pub merkle_root: String,
        pub elements: Vec<String>,
        pub merkle_proofs: Vec<String>,
    }

    let depth = ethash::calc_dataset_depth(dag.epoch);
    let mut output = BlockWithProofs {
        proof_length: depth as _,
        header_rlp: rlp_encoded_str.trim().to_owned(),
        merkle_root: hex::encode(&root.0),
        elements: Vec::with_capacity(depth * 4),
        merkle_proofs: Vec::with_capacity(depth * 2),
    };
    for index in &indices {
        // these proofs could be serde to json files.
        let (element, _leaf_hash, proofs) =
            tree.generate_proof(*index as _, depth);
        let els = element.into_h256_array();
        output.elements.extend(els.iter().map(|v| hex::encode(&v)));
        output
            .merkle_proofs
            .extend(proofs.iter().map(|v| hex::encode(&v.0)));
    }

    let json = serde_json::to_vec_pretty(&output).unwrap();
    std::fs::write("target/output.json", &json).unwrap();

    // read it again to use the proofs.
    let input: BlockWithProofs = serde_json::from_slice(&json).unwrap();

    let depth = input.proof_length;
    let proofs_chunks = input.merkle_proofs.chunks_exact((depth) as usize);
    let element_chunks = input.elements.chunks_exact(4);
    let iter = proofs_chunks.zip(element_chunks).zip(indices);
    for ((proofs, parts), index) in iter {
        let parts: Vec<_> = parts
            .iter()
            .map(|v| hex::decode(v).unwrap())
            .map(|mut v| {
                v.reverse(); // this needed to be Little Endian.
                H256::from_slice(&v)
            })
            .collect();
        let mut h256_array = [H256::zero(); 4];
        h256_array.copy_from_slice(&parts);
        let element = Word::from(h256_array);

        let proofs: Vec<_> = proofs
            .iter()
            .map(|v| hex::decode(v).unwrap())
            .map(|v| Hash::from(v.as_slice()))
            .collect();
        let included = ethash::mtree::verify_merkle_proof(
            &element,
            &proofs,
            depth as usize,
            index as usize,
            root,
        );
        assert!(
            included,
            "index: {}, element: {}",
            index,
            hex::encode(&element.0)
        );
    }
}

#[test]
fn mix_hash_2() {
    let rlp_encoded_str = include_str!("fixtures/2.rlp");
    let rlp_encoded = hex::decode(rlp_encoded_str.trim()).unwrap();
    let header: types::BlockHeader = rlp::decode(&rlp_encoded).unwrap();
    dbg!(&header);
    let dag = ethash::LightDAG::<ethash::EthereumPatch>::new(header.number);
    let (mix_hash, _) = dag.hashimoto(header.seal_hash(), header.nonce);
    assert_eq!(mix_hash, header.mix_hash);
}

#[test]
fn mix_hash_10234011() {
    let rlp_encoded_str = include_str!("fixtures/10234011.rlp");
    let rlp_encoded = hex::decode(rlp_encoded_str.trim()).unwrap();
    let header: types::BlockHeader = rlp::decode(&rlp_encoded).unwrap();
    dbg!(&header);
    let dag = ethash::LightDAG::<ethash::EthereumPatch>::new(header.number);
    let (mix_hash, _) = dag.hashimoto(header.seal_hash(), header.nonce);
    assert_eq!(mix_hash, header.mix_hash);
}
