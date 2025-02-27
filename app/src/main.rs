#![no_main]
pico_sdk::entrypoint!(main);

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe_traits::{Serialize, Deserialize, FheEncoder, FheEncrypter, DeserializeParametrized};
use pico_sdk::io::{commit, read_as};
use rand::thread_rng;
use std::sync::Arc;
use serde;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct FheInput {
    pub params: Vec<u8>,
    pub pk: Vec<u8>,
    pub input: Vec<u64>,
}

pub fn main() {
    // Read the serialized input payload from the environment.
    let fhe_input: FheInput = read_as();

    // Deserialize FHE parameters.
    let params = Arc::new(BfvParameters::try_deserialize(&fhe_input.params)
        .expect("Failed to deserialize parameters"));
    // Reconstruct the public key.
    let pk: PublicKey = PublicKey::from_bytes(&fhe_input.pk, &params)
        .expect("Failed to deserialize public key");
    let input = fhe_input.input;

    // (Example) check that only one vote was cast.
    let sum: u64 = input.iter().sum();
    if sum > 1 {
        panic!("Too many votes cast");
    }

    // Encrypt the input.
    let mut rng = thread_rng();
    let pt = Plaintext::try_encode(&input, Encoding::poly(), &params)
        .expect("Encoding failed");
    let ct: Ciphertext = pk.try_encrypt(&pt, &mut rng)
        .expect("Encryption failed");

    // Commit the resulting ciphertext as the public output.
    commit(&ct.to_bytes());
}
