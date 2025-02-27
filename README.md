Build program
```bash
cd app
CARGO_NET_GIT_FETCH_WITH_CLI=true RUST_LOG=info cargo pico build
```

Prove program with Pico
```bash
cd prover
RUST_LOG=info cargo run --release  
```