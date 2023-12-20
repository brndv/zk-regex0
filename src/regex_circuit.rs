use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine,G1};
use halo2_base::halo2_proofs::plonk::{ConstraintSystem, Error,VerifyingKey,ProvingKey,keygen_pk,keygen_vk,create_proof,verify_proof};
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{Column, Instance},
};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::{dev::{MockProver,CircuitCost, CircuitLayout}, halo2curves::bn256::Fr, plonk::Circuit};
use halo2_base::Context;
use halo2_base::{utils::PrimeField, ContextParams, SKIP_FIRST_PASS};
use halo2_regex::{
    defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef},
    RegexVerifyConfig,
};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
//use snark_verifier::util::arithmetic::PrimeField;
use std::marker::PhantomData;

use fancy_regex::Regex;
use itertools::Itertools;
use rand::rngs::OsRng;

pub const MAX_STRING_LEN: usize = 128;
pub const K: usize = 14;

/// 1. Define a configure of our example circuit.
#[derive(Clone, Debug)]
pub struct ExampleConfig<F: PrimeField> {
    inner: RegexVerifyConfig<F>,
    /// Masked Characters Instance
    masked_str_instance: Column<Instance>,
    /// Substrid Instance
    substr_ids_instance: Column<Instance>,
}

/// 2. Define an example circuit.
#[derive(Default, Clone, Debug)]
pub struct RegexCircuit<F: PrimeField> {
    // The bytes of the input string.
    characters: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> RegexCircuit<F> {
    /// The number of advice columns in [`FlexGateConfig`].
    const NUM_ADVICE: usize = 2;
    /// The number of fix columns in [`FlexGateConfig`].
    const NUM_FIXED: usize = 1;
    /// Path to save all string regex DFA transition table
    const ALLSTR_PATH: &str = "./lookups/ex_allstr.txt";
}

impl<F: PrimeField> Circuit<F> for RegexCircuit<F> {
    type Config = ExampleConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            characters: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let all_regex_def1 = AllstrRegexDef::read_from_text(Self::ALLSTR_PATH);
        let substr_defs = ["./lookups/ex_substr_id1.txt"].into_iter()
                            .map(|path| 
                                SubstrRegexDef::read_from_text(path)
                            ).collect();
        let gate = FlexGateConfig::<F>::configure(
            meta,
            halo2_base::gates::flex_gate::GateStrategy::Vertical,
            &[Self::NUM_ADVICE],
            Self::NUM_FIXED,
            0,
            K,
        );
        let regex_defs = vec![RegexDefs {
            allstr: all_regex_def1,
            substrs: substr_defs,
        }];
        let inner = RegexVerifyConfig::configure(meta, MAX_STRING_LEN, gate, regex_defs);
        let masked_str_instance = meta.instance_column();
        meta.enable_equality(masked_str_instance);
        let substr_ids_instance = meta.instance_column();
        meta.enable_equality(substr_ids_instance);
        Self::Config { inner, masked_str_instance, substr_ids_instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        config.inner.load(&mut layouter)?;
        
        let mut first_pass = SKIP_FIRST_PASS;
        let gate = config.inner.gate().clone();
        
        let mut masked_char_cells = vec![];
        let mut masked_substr_id_cells = vec![];
        layouter.assign_region(
            || "regex",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );
                let ctx = &mut aux;
                let result = config.inner.match_substrs(ctx, &self.characters)?;

                for (assigned_char, assigned_substr_id) in result
                    .masked_characters
                    .iter()
                    .zip(result.all_substr_ids.iter())
                {
                    masked_char_cells.push(assigned_char.cell());
                    masked_substr_id_cells.push(assigned_substr_id.cell());
                }

                
                Ok(())
            },
        )?;
        for (idx, cell) in masked_char_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.masked_str_instance, idx)?;
        }
        for (idx, cell) in masked_substr_id_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.substr_ids_instance, idx)?;
        }
        Ok(())
    }
}

pub fn create_circuit(characters: Vec<u8>) -> RegexCircuit<Fr> {
    RegexCircuit::<Fr> {
        characters,
        _marker: PhantomData,
    }
}

#[cfg(not(target_family = "wasm"))]
pub fn draw_circuit<F: PrimeField>(k: u32, circuit: &RegexCircuit<F>) {
    use plotters::prelude::*;
    
    let base = BitMapBackend::new("layout.png", (1600, 1600)).into_drawing_area();
    base.fill(&WHITE).unwrap();
    let base = base
        .titled("Example Regex Circuit", ("sans-serif", 24))
        .unwrap();

    CircuitLayout::default()
        .show_equality_constraints(true)
        .render(k, circuit, &base)
        .unwrap();
}

pub fn print_circuit_cost(circuit: &RegexCircuit<Fr>) {
    println!(
        "{:?}",
        CircuitCost::<G1, RegexCircuit<Fr>>::measure(
            (K as u128).try_into().unwrap(),
            circuit
        )
    );
}

pub fn get_substr(input_str: &str, regexes: &[String]) -> Option<(usize, String)> {
    let regexes = regexes
        .into_iter()
        .map(|raw| Regex::new(&raw).unwrap())
        .collect_vec();
    let mut start = 0;
    let mut substr = input_str;

    for regex in regexes.into_iter() {
        // println!(r"regex {}", regex);
        match regex.find(substr).unwrap() {
            Some(m) => {
                start += m.start();
                substr = m.as_str();
            }
            None => {
                return None;
            }
        };
    }
    Some((start, substr.to_string()))
}

pub fn gen_masked_instance(text :&str) -> (Vec<Fr>,Vec<Fr>){
    let mut expected_masked_chars = vec![Fr::from(0); MAX_STRING_LEN];
    let mut expected_masked_substr_ids = vec![Fr::from(0); MAX_STRING_LEN];
    let correct_substrs = vec![
        get_substr(&text, &[r"(?<=from:).*@.*(?=to)".to_string(), "<?(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+>?".to_string(), "(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+@(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|\\.|-)+".to_string()]).unwrap(),
    ];

    println!("Matched sub-strings(public:true):{:?}",correct_substrs);

    for (substr_idx, (start, chars)) in correct_substrs.iter().enumerate() {
        for (idx, char) in chars.as_bytes().iter().enumerate() {
            expected_masked_chars[start + idx] = Fr::from(*char as u64);
            expected_masked_substr_ids[start + idx] = Fr::from(substr_idx as u64 + 1);
        }
    }
    (expected_masked_chars,expected_masked_substr_ids)
}



// Generates setup parameters using k, which is the number of rows of the circuit
// can fit in and must be a power of two
pub fn generate_setup_params(
    k: u32,
) -> ParamsKZG<Bn256>{
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

// Generates the verifying and proving keys. We can pass in an empty circuit to generate these
pub fn generate_keys(
    params: &ParamsKZG<Bn256>,
    emp_circuit: &RegexCircuit<Fr>,
) -> (ProvingKey<G1Affine>, VerifyingKey<G1Affine>) {
    // just to emphasize that for vk, pk we don't need to know the value of `x`
    let vk = keygen_vk(params, emp_circuit).unwrap();
    let pk = keygen_pk(params, vk.clone(), emp_circuit).unwrap();
    (pk, vk)
}

// Runs the mock prover and prints any errors
pub fn run_mock_prover(
    k: u32,
    circuit: &RegexCircuit<Fr>,
    masked_chars: &Vec<Fr>,
    masked_substr_ids: &Vec<Fr>,
) {
    let prover = MockProver::run(k, circuit, vec![masked_chars.clone(),masked_substr_ids.clone()]).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("MockProver OK"),
        Err(e) => println!("err {:#?}", e),
    }
}

pub fn generate_proof(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: &RegexCircuit<Fr>,
    pub_input1: &Vec<Fr>,
    pub_input2: &Vec<Fr>,
) -> Vec<u8> {
    println!("Generating proof...");
    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit.clone()],
            &[&[pub_input1,pub_input2]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    proof
}
// Verifies the proof 
pub fn verify(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    pub_input1: &Vec<Fr>,
    pub_input2: &Vec<Fr>,
    proof: Vec<u8>,
) -> Result<(), Error> {
    
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&verifier_params);
    verify_proof::<_, VerifierGWC<_>, _, _, _>(
        verifier_params,
        &vk,
        strategy,
        &[&[pub_input1,pub_input2]],
        &mut transcript,
    )
}


