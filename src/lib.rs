use ark_bls12_381::{Bls12_381, Config, Fr as F, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    pairing::Pairing,
    short_weierstrass::Affine,
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};

use derive_more::Display;

#[derive(Debug, Display)]
pub enum ProofError {
    #[display(fmt = "Cannot generate valid proof: division remainder is non-zero")]
    InvalidProof,
    #[display(fmt = "Polynomial division failed")]
    DivisionError,
}
impl std::error::Error for ProofError {}

struct KZGCommitment {
    trusted_setup_g1: Vec<G1Affine>,
    trusted_setup_g2: Vec<G2Affine>,
}

impl KZGCommitment {
    pub fn new(degree: usize) -> Self {
        let (trusted_setup_g1, trusted_setup_g2) = Self::trusted_setup(degree);
        Self {
            trusted_setup_g1,
            trusted_setup_g2,
        }
    }

    fn lagrange_interpolation(points: &Vec<(F, F)>) -> DensePolynomial<F> {
        let mut result: DensePolynomial<F> = DensePolynomial::zero();
        for (index, &(x_i, y_i)) in points.into_iter().enumerate() {
            let mut term = DensePolynomial::from_coefficients_vec(vec![y_i]);
            for (j, &(x_j, _)) in points.iter().enumerate() {
                if j != index {
                    let scalar = (x_i - x_j).inverse().unwrap();
                    let numerator = DensePolynomial::from_coefficients_vec(vec![
                        -x_j * scalar,
                        F::one() * scalar,
                    ]);
                    term = &term * &numerator;
                }
            }

            result += &term;
        }
        result
    }

    fn trusted_setup(degree: usize) -> (Vec<G1Affine>, Vec<G2Affine>) {
        let mut rng = ark_std::test_rng();
        let tau = F::rand(&mut rng);
        let mut trusted_setup_g1: Vec<G1Affine> = Vec::new();
        let mut trusted_setup_g2: Vec<G2Affine> = Vec::new();
        for i in 0..degree {
            let tau_i = tau.pow([i as u64]);
            trusted_setup_g1.push((G1Affine::generator() * tau_i).into_affine());
            trusted_setup_g2.push((G2Affine::generator() * tau_i).into_affine());
        }

        (trusted_setup_g1, trusted_setup_g2)
    }

    pub fn vector_to_polynomial(vector: &Vec<i32>) -> DensePolynomial<F> {
        let y_s: Vec<F> = vector.iter().map(|&y| F::from(y)).collect();
        let x_s: Vec<F> = (0..vector.len()).map(|val| F::from(val as u32)).collect();
        let points: Vec<(F, F)> = x_s.into_iter().zip(y_s.into_iter()).collect();
        Self::lagrange_interpolation(&points)
    }

    fn evaluate_polynomial_at_g1_setup(&self, polynomial: &DensePolynomial<F>) -> G1Affine {
        let mut result: G1Affine = G1Affine::zero();
        let poly_coeffs = polynomial.coeffs();
        for (index, coeff) in poly_coeffs.into_iter().enumerate() {
            let temp = (self.trusted_setup_g1[index] * coeff).into_affine();
            result = (result + temp).into_affine();
        }
        result
    }

    fn evaluate_polynomial_at_g2_setup(&self, polynomial: &DensePolynomial<F>) -> G2Affine {
        let mut result: G2Affine = G2Affine::zero();
        let poly_coeffs = polynomial.coeffs();
        for (index, coeff) in poly_coeffs.into_iter().enumerate() {
            let temp = (self.trusted_setup_g2[index] * coeff).into_affine();
            result = (result + temp).into_affine();
        }
        result
    }

    pub fn commit_polynomial(&self, polynomial: &DensePolynomial<F>) -> G1Affine {
        self.evaluate_polynomial_at_g1_setup(polynomial)
    }

    pub fn generate_proof(
        &self,
        polynomial: &DensePolynomial<F>,
        points: &Vec<(F, F)>,
    ) -> Result<G1Affine, ProofError> {
        // lagrange interpolation
        let point_polynomial = Self::lagrange_interpolation(&points);
        let numerator = polynomial - &point_polynomial;
        let mut denominator = DensePolynomial::from_coefficients_vec(vec![F::from(1)]);
        for (x, _) in points {
            denominator =
                &denominator * &DensePolynomial::from_coefficients_vec(vec![-*x, F::from(1)]);
        }
        let (q, r) = DenseOrSparsePolynomial::from(numerator)
            .divide_with_q_and_r(&DenseOrSparsePolynomial::from(denominator))
            .unwrap();

        if r != DensePolynomial::zero() {
            return Err(ProofError::InvalidProof);
        }

        Ok(self.evaluate_polynomial_at_g1_setup(&q))
    }

    pub fn verify_proof(
        &self,
        commitment: &G1Affine,
        points: &Vec<(F, F)>,
        proof: &G1Affine,
    ) -> bool {
        let point_polynomial = Self::lagrange_interpolation(&points);

        let mut vanishing_polynomial = DensePolynomial::from_coefficients_vec(vec![F::from(1)]);
        for (x, _) in points {
            vanishing_polynomial = &vanishing_polynomial
                * &DensePolynomial::from_coefficients_vec(vec![-*x, F::from(1)]);
        }

        let z_s: G2Affine = self.evaluate_polynomial_at_g2_setup(&vanishing_polynomial);
        let i_s: G1Affine = self.evaluate_polynomial_at_g1_setup(&point_polynomial);

        let lhs = Bls12_381::pairing(proof, z_s);
        let g1_lhs = *commitment - i_s;
        let rhs = Bls12_381::pairing(g1_lhs.into_affine(), G2Affine::generator());

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::ProofError;

    use super::KZGCommitment;
    use ark_bls12_381::{Fr as F, G1Affine, G2Affine};
    use ark_poly::{polynomial, Polynomial};
    use rand::{prelude::SliceRandom, Rng};

    #[test]
    fn test_vec_to_poly() {
        let vector = generate_random_vec();
        let polynomial = KZGCommitment::vector_to_polynomial(&vector);
        let random_points = random_points(&vector);
        for point in random_points {
            assert_eq!(
                polynomial.evaluate(&point.0),
                point.1,
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

    fn generate_random_vec() -> Vec<i32> {
        let mut rng = rand::thread_rng();

        // Generate a random length between 1 and 20
        let length = rng.gen_range(1..=50);
        println!("Generating vector with length: {}", length);
        // Generate the vector with random numbers
        (0..length).map(|_| rng.gen_range(-1000..=1000)).collect()
    }

    fn random_points(vec: &Vec<i32>) -> Vec<(F, F)> {
        let mut rng = rand::thread_rng();
        let count = rng.gen_range(1..vec.len());
        println!("Fetching {} points", count);
        vec.iter()
            .enumerate()
            .collect::<Vec<(usize, &i32)>>()
            .choose_multiple(&mut rng, count)
            .map(|&(index, item)| (F::from(index as i32), F::from(item.clone())))
            .collect()
    }
}
