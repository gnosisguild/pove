// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use fhe::bfv::BfvParameters;
use fhe_traits::Deserialize;
use methods::{POVE_ELF, POVE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // An executor environment describes the configurations for the zkVM
    // including program inputs.
    // An default ExecutorEnv can be created like so:
    // `let env = ExecutorEnv::builder().build().unwrap();`
    // However, this `env` does not have any inputs.
    //
    // To add guest input to the executor environment, use
    // ExecutorEnvBuilder::write().
    // To access this method, you'll need to use ExecutorEnv::builder(), which
    // creates an ExecutorEnvBuilder. When you're done adding input, call
    // ExecutorEnvBuilder::build().

    let degree: u64 = 1024;
    let plaintext_modulus: u64 = 65537;
    let moduli: Vec<u64> = vec![1152921504606584833];

    let env = ExecutorEnv::builder()
        .write(&degree)
        .unwrap()
        .write(&plaintext_modulus)
        .unwrap()
        .write(&moduli)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove(env, POVE_ELF).unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;

    // TODO: Implement code for retrieving receipt journal here.

    // For example:
    let output: Vec<u8> = receipt.journal.decode().unwrap();

    let param_bytes: [u8; 20] = output.try_into().unwrap();

    let _params = BfvParameters::try_deserialize(&param_bytes).unwrap();

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt.verify(POVE_ID).unwrap();
}
