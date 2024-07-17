# KZG Commitment Library

This repository contains a Rust implementation of KZG Commitments, a cryptographic primitive used for polynomial commitments. The library provides functionality to generate, commit, and verify polynomial commitments.

Blog post on implementing [KZG commitment scheme](https://cleanpegasus.medium.com/implementing-kzg-commitment-scheme-a18bf8ec057a)
You can find the python version of this code [here](https://github.com/CleanPegasus/kzg-commitment-python)

## Features
- Vector to Polynomial: Convert a vector of elements to polynomial form.
- Polynomial Commitment: Commit to a polynomial
- Proof Generation: Generate a proof for a given set of points from the vector.
- Proof Verification: Verify the correctness of the proofs generated.

## Installation
To use this library, add the following to your `Cargo.toml`
```toml
kzg-commitment = "0.1.3"
```

## Usage
Here is a basic example of how to use the library:

```rust

use kzg_commitment::KZGCommitment;
use ark_bls12_381::{Fr as F};

fn main() {
    let kzg = KZGCommitment::new(50);
    let vector = vec![F::from(120), F::from(-15), F::from(60), F::from(80)];
    let polynomial = KZGCommitment::vector_to_polynomial(&vector);
    let commitment = kzg.commit_polynomial(&polynomial);
    let points = vec![(F::from(0), F::from(120)), (F::from(1), F::from(-15))];
    let proof = kzg.generate_proof(&polynomial, &random_points).unwrap();
    let verification = kzg.verify_proof(&commitment, &random_points, &proof);

    assert!(verification, "Verification failed");
}
```

### Testing
To run the tests, use the following command:
```bash
cargo test
```

### Example Tests
- `test_vec_to_poly`: Tests the conversion of a vector to a polynomial and evaluates it at random points.
- `test_verify_proof_valid`: Tests the generation and verification of a valid proof.
- `test_invalid_proof_generation`: Tests the generation of an invalid proof and ensures the correct error is returned.
- `test_invalid_proof_verification`: Tests the verification of an invalid proof and ensures the correct error is returned.

### TODO
- [x] Use Finite Field for vectors instead of i32
- [ ] Add support for precomputed powers_of_tau (trusted_setup)
- [ ] Add more tests for invalid proof verification
- [ ] Add benchmarks


### Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgements
KZG Commitments - More information about KZG Commitments.

This project was inspired by Dankrad Feist's blog post on [KZG Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html).

