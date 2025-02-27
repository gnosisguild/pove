use fhe::bfv::{BfvParametersBuilder, PublicKey, SecretKey,Encoding, Ciphertext};
use fhe_traits::{Serialize, FheDecoder, DeserializeParametrized, FheDecrypter};
use pico_sdk::{client::DefaultProverClient, init_logger};
use rand::thread_rng;
use std::fs;
// Bundle together the input for the guest.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FheInput {
    pub params: Vec<u8>,
    pub pk: Vec<u8>,
    pub input: Vec<u64>,
}

pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

fn main() {
    // Initialize logging.
    init_logger();

    // Build FHE parameters.
    let degree: u64 = 1024;
    let plaintext_modulus: u64 = 65537;
    let moduli: Vec<u64> = vec![1152921504606584833];

    let params = BfvParametersBuilder::new()
        .set_degree(degree as usize)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .expect("Failed to build parameters");

    let mut rng = thread_rng();
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // Prepare the vote/input. (For example: 0 or 1)
    let input: Vec<u64> = vec![0, 1];
    let sum: u64 = input.iter().sum();

    // Bundle all inputs into one structure.
    let fhe_input = FheInput {
        params: params.to_bytes(),
        pk: pk.to_bytes(),
        input,
    };

    // Load the guest ELF file.
    let elf = load_elf("../app/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client.
    let client = DefaultProverClient::new(&elf);
    let stdin_builder = client.get_stdin_builder();

    // Write the FheInput struct directly into the guest using Pico's serialization.
    stdin_builder.borrow_mut().write(&fhe_input);

    // Generate the proof.
    let proof = client.prove_fast().expect("Failed to generate proof");

    // Extract and print the public output (ciphertext bytes).
    let public_buffer = proof.pv_stream.expect("No public output found");
    println!("Public output ciphertext: {:?}", public_buffer);


    // Decrypt the public output.
    let ct = Ciphertext::from_bytes(&public_buffer, &params).expect("Failed to deserialize ciphertext");
    let pt = sk.try_decrypt(&ct).expect("Failed to decrypt ciphertext");
    let decoded_pt = Vec::<u64>::try_decode(&pt, Encoding::poly()).expect("Failed to decode plaintext");
    println!("Decrypted public output: {:?}", decoded_pt);

    assert_eq!(decoded_pt, vec![sum]);
}
