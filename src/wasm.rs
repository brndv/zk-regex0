use crate::regex_circuit::{generate_setup_params,create_circuit,gen_masked_instance,generate_keys,generate_proof,verify};
use std::io::BufReader;
use halo2_base::halo2_proofs::plonk::Circuit;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256,Fr},
    poly::commitment::Params, 
    plonk::keygen_vk
};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn copy_vec_to_u8arr(v: &Vec<u8>) -> Uint8Array {
    let u8_arr = Uint8Array::new_with_length(v.len() as u32);
    u8_arr.copy_from(v);
    u8_arr
}

#[wasm_bindgen]
pub fn setup_params(k: u32) -> Uint8Array {
    log("running setup");
    
    // Generate setup params
    let params = generate_setup_params(k); 
    let mut buf = vec![];
    params.write(&mut buf).expect("Can write params");

    copy_vec_to_u8arr(&buf)
}

#[wasm_bindgen]
pub fn proof_generate(
    text : &str,
    params_bytes: &[u8]
) -> Uint8Array {
    log("proving...");
    
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_bytes)).expect("params should not fail to read");

    let characters: Vec<u8> = text
        .chars()
        .map(|c| c as u8)
        .collect();
    
    let circuit = create_circuit(characters);
    let (masked_chars, masked_substr_ids) = gen_masked_instance(text);
    // Generate proving key
    let empty_circuit = circuit.without_witnesses();
    let (pk, _vk) = generate_keys(&params, &empty_circuit);
    
    // Generate proof
    let proof = generate_proof(&params, &pk, &circuit, &masked_chars,&masked_substr_ids);
    
    copy_vec_to_u8arr(&proof)
}

#[wasm_bindgen]
pub fn proof_verify(
    params_bytes: &[u8], 
    expected_masked_chars: Vec<u8>,
    expected_masked_substr_ids: Vec<u8>, 
    proof: &[u8]
) -> bool {
    log("verifying...");

    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(params_bytes)).expect("params should not fail to read");

    // Generate verifying key
    let empty_circuit = create_circuit(vec![]);
    let vk = keygen_vk(&params, &empty_circuit).expect("vk should not fail to generate");

    // Transform params for verify function
    let expected_masked_chars_fr = expected_masked_chars.iter().map(|n| {Fr::from(*n as u64)}).collect();
    let expected_masked_substr_ids_fr = expected_masked_substr_ids.iter().map(|n| {Fr::from(*n as u64)}).collect();
    let proof_vec = proof.to_vec();

    // Verify the proof and public input
    let ret_val = verify(&params, &vk, &expected_masked_chars_fr,&expected_masked_substr_ids_fr, proof_vec);
    match ret_val {
        Err(_) => false,
        _ => true,
    }
}
