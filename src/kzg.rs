use num_bigint::BigInt;
use ark_bls12_381::{Bls12_381, Config, Fr as F, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    pairing::Pairing,
    short_weierstrass::Affine,
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, UniformRand, Zero, BigInteger256};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};
// use num_traits::{Zero, One, FromPrimitive};

use derive_more::Display;

#[derive(Debug, Display)]
pub enum ProofError {
    #[display(fmt = "Cannot generate valid proof: division remainder is non-zero")]
    InvalidProof,
    #[display(fmt = "Polynomial division failed")]
    DivisionError,
}
impl std::error::Error for ProofError {}

/// A struct representing a KZG Commitment.
///
/// KZG Commitments are cryptographic primitives used for polynomial commitments.
/// This struct contains the trusted setup parameters required for generating and verifying commitments.
pub struct KZGCommitment {
    /// The trusted setup parameters in G1 group.
    trusted_setup_g1: Vec<G1Affine>,
    /// The trusted setup parameters in G2 group.
    trusted_setup_g2: Vec<G2Affine>,
}

impl KZGCommitment {

    /// Creates a new `KZGCommitment` instance with the given degree.
    ///
    /// This function initializes the trusted setup parameters for the specified degree
    /// and returns a new instance of `KZGCommitment`.
    pub fn new(degree: usize) -> Self {
        let (trusted_setup_g1, trusted_setup_g2) = Self::trusted_setup(degree);
        Self {
            trusted_setup_g1,
            trusted_setup_g2,
        }
    }

    /// Performs lagrange interpolation on a set of points under a finite field
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

    /// Generates G1 and G2 group points for the trusted setup and discards the toxic waste
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
    /// Converts a vector of field elements into a polynomial using Lagrange interpolation.
    ///
    /// This function takes a reference to a vector of field elements and returns a `DensePolynomial<F>`
    /// that represents the polynomial passing through the points (0, vector[0]), (1, vector[1]), ..., (n-1, vector[n-1]),
    /// where `n` is the length of the input vector.
    pub fn vector_to_polynomial(vector: &Vec<F>) -> DensePolynomial<F> {
        let y_s: Vec<F> = vector.iter().map(|&y| F::from(y)).collect();
        let x_s: Vec<F> = (0..vector.len()).map(|val| F::from(val as u32)).collect();
        let points: Vec<(F, F)> = x_s.into_iter().zip(y_s.into_iter()).collect();
        Self::lagrange_interpolation(&points)
    }
    
    /// Evaluation of the given polynomial using trusted setup at G1 group
    fn evaluate_polynomial_at_g1_setup(&self, polynomial: &DensePolynomial<F>) -> G1Affine {
        let mut result: G1Affine = G1Affine::zero();
        let poly_coeffs = polynomial.coeffs();
        for (index, coeff) in poly_coeffs.into_iter().enumerate() {
            let temp = (self.trusted_setup_g1[index] * coeff).into_affine();
            result = (result + temp).into_affine();
        }
        result
    }

    /// Evaluation of the given polynomial using trusted setup at G2 group
    fn evaluate_polynomial_at_g2_setup(&self, polynomial: &DensePolynomial<F>) -> G2Affine {
        let mut result: G2Affine = G2Affine::zero();
        let poly_coeffs = polynomial.coeffs();
        for (index, coeff) in poly_coeffs.into_iter().enumerate() {
            let temp = (self.trusted_setup_g2[index] * coeff).into_affine();
            result = (result + temp).into_affine();
        }
        result
    }

    /// Commits to a polynomial using the KZG commitment scheme.
    ///
    /// This function takes a reference to a polynomial and returns a commitment in the G1 group.
    /// The commitment is generated by evaluating the polynomial at the trusted setup parameters in G1.
    pub fn commit_polynomial(&self, polynomial: &DensePolynomial<F>) -> G1Affine {
        self.evaluate_polynomial_at_g1_setup(polynomial)
    }
    

    /// Generates a proof for a given polynomial and a set of points using the KZG commitment scheme.
    ///
    /// This function performs Lagrange interpolation on the given points to create a polynomial,
    /// then computes the quotient and remainder of the division of the original polynomial by the
    /// interpolated polynomial. If the remainder is zero, it returns the proof.
    pub fn generate_proof(
        &self,
        polynomial: &DensePolynomial<F>,
        points: &Vec<(F, F)>,
    ) -> Result<G1Affine, ProofError> {
        // lagrange interpolation
        let points_ff: Vec<(F, F)> = points.into_iter().map(|&(x, y)| (F::from(x), F::from(y))).collect();
        let point_polynomial = Self::lagrange_interpolation(&points_ff);
        let numerator = polynomial - &point_polynomial;
        let mut denominator = DensePolynomial::from_coefficients_vec(vec![F::from(1)]);
        for (x, _) in points_ff {
            denominator =
                &denominator * &DensePolynomial::from_coefficients_vec(vec![-x, F::from(1)]);
        }
        let (q, r) = DenseOrSparsePolynomial::from(numerator)
            .divide_with_q_and_r(&DenseOrSparsePolynomial::from(denominator))
            .unwrap();

        if r != DensePolynomial::zero() {
            return Err(ProofError::InvalidProof);
        }

        Ok(self.evaluate_polynomial_at_g1_setup(&q))
    }

    /// Verifies a proof for a given polynomial commitment using the KZG commitment scheme.
    ///
    /// This function checks if the provided proof is valid for the given commitment and points.
    /// It performs Lagrange interpolation on the points to create a polynomial, constructs the vanishing polynomial,
    /// and then uses BLS12_381 pairings to verify the proof.
    pub fn verify_proof(
        &self,
        commitment: &G1Affine,
        points: &Vec<(F, F)>,
        proof: &G1Affine,
    ) -> bool {
        let points_ff: Vec<(F, F)> = points.into_iter().map(|&(x, y)| (F::from(x), F::from(y))).collect();
        let point_polynomial = Self::lagrange_interpolation(&points_ff);
        let mut vanishing_polynomial = DensePolynomial::from_coefficients_vec(vec![F::from(1)]);
        for (x, _) in points_ff {
            vanishing_polynomial = &vanishing_polynomial
                * &DensePolynomial::from_coefficients_vec(vec![-x, F::from(1)]);
        }

        let z_s: G2Affine = self.evaluate_polynomial_at_g2_setup(&vanishing_polynomial);
        let i_s: G1Affine = self.evaluate_polynomial_at_g1_setup(&point_polynomial);

        let lhs = Bls12_381::pairing(proof, z_s);
        let g1_lhs = *commitment - i_s;
        let rhs = Bls12_381::pairing(g1_lhs.into_affine(), G2Affine::generator());

        lhs == rhs
    }
}

