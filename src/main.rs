use halo2_regex::vrm::DecomposedRegexConfig;
use std::{path::Path,fs::File};


use zk_regex::regex_circuit::*;

#[cfg(not(target_family = "wasm"))]
fn main() {
    let regex1_decomposed: DecomposedRegexConfig =
                serde_json::from_reader(File::open("./regexes/regex_example.json").unwrap())
                    .unwrap();
    
    regex1_decomposed
        .gen_regex_files(
            &Path::new("./lookups/ex_allstr.txt").to_path_buf(),
            &[Path::new("./lookups/ex_substr_id1.txt").to_path_buf()],
        )
        .unwrap();
    let text = "email  from: vital vitalik@gmail to: some some@outlook.com   etc.";
    let characters: Vec<u8> = text
        .chars()
        .map(|c| c as u8)
        .collect();

    let circuit = create_circuit(characters);

    // Generate instance
    let (expected_masked_chars, expected_masked_substr_ids) = gen_masked_instance(text);
    

    //Draw circuit layout
    draw_circuit(K as u32, &circuit);
    //Circuit Cost Overview
    print_circuit_cost(&circuit);

    //MockProve
    run_mock_prover(
        K as u32,
        &circuit,
        &expected_masked_chars, 
        &expected_masked_substr_ids,
    );


    // Generate and verify proofs
    //let (masked_chars, masked_substr_ids) = gen_masked_instance(text);
    let params = generate_setup_params(K as u32);
    let empty_circuit = create_circuit(vec![]);
    
    // generate proving and verifying keys
    let (pk, vk) = generate_keys(&params, &empty_circuit);
    // Generate proof
    let proof = generate_proof(&params, &pk, &circuit, &expected_masked_chars,&expected_masked_substr_ids);
   
    // Verify proof
    let verify = verify(&params, &vk, &expected_masked_chars,&expected_masked_substr_ids, proof);
    println!("Proof verification result: {:?}", verify);
    
   
}
