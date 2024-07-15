

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::kzg::ProofError;

    use crate::kzg::KZGCommitment;

    use ark_bls12_381::{Fr as F, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_poly::{polynomial, Polynomial};
    use rand::{prelude::SliceRandom, Rng};

    #[test]
    fn test_vec_to_poly() {
        let vector = generate_random_vec();
        let polynomial = KZGCommitment::vector_to_polynomial(&vector);
        let random_points = random_points(&vector);
        for (x, y) in random_points {
            assert_eq!(
                polynomial.evaluate(&F::from(x)),
                F::from(y),
                "Vector interpolation is wrong"
            );
        }
    }

    #[test]
    fn test_verify_proof_valid() {
        let kzg = KZGCommitment::new(50);
        let vector = generate_random_vec();
        let polynomial = KZGCommitment::vector_to_polynomial(&vector);
        let random_points = random_points(&vector);
        let commitment = kzg.commit_polynomial(&polynomial);
        let proof = kzg.generate_proof(&polynomial, &random_points).unwrap();
        let verification = kzg.verify_proof(&commitment, &random_points, &proof);

        assert!(verification, "Verification is false");
    }

    #[test]
    fn test_invalid_proof_generation() {
        let kzg = KZGCommitment::new(50);
        let vector = generate_random_vec();
        let polynomial = KZGCommitment::vector_to_polynomial(&vector);

        let invalid_vector = generate_random_vec();
        let invalid_points = random_points(&invalid_vector);

        let proof_result = kzg.generate_proof(&polynomial, &invalid_points);
        match proof_result {
          Ok(_) => panic!("Expected an error, but proof generation succeeded"),
          Err(ProofError::InvalidProof) => {
              // Test passes if we get the InvalidProof error
          },
          Err(e) => panic!("Expected InvalidProof error, but got: {:?}", e),
      }
    }

    #[test]
    fn test_invalid_proof_verification() {
        let kzg = KZGCommitment::new(50);
        let vector = generate_random_vec();
        let polynomial = KZGCommitment::vector_to_polynomial(&vector);
        let commitment = kzg.commit_polynomial(&polynomial);

        let invalid_vector = generate_random_vec();
        let invalid_points = random_points(&invalid_vector);
        let invalid_proof = (G1Affine::generator() * F::from(10)).into_affine();

        let verification = kzg.verify_proof(&commitment, &invalid_points, &invalid_proof);

        assert!(!verification, "The verification should be false");
    }

    fn generate_random_vec() -> Vec<F> {
        let mut rng = rand::thread_rng();
        let length = rng.gen_range(1..=50);
        println!("Generating vector with length: {}", length);
        (0..length).map(|_| F::from(rng.gen_range(-1000..=1000))).collect()
    }

    fn random_points(vec: &Vec<F>) -> Vec<(F, F)> {
        let mut rng = rand::thread_rng();
        let count = rng.gen_range(1..vec.len());
        println!("Fetching {} points", count);
        vec.iter()
            .enumerate()
            .collect::<Vec<(usize, &F)>>()
            .choose_multiple(&mut rng, count)
            .map(|&(index, item)| (F::from(index as u64), item.clone()))
            .collect()
    }
}
