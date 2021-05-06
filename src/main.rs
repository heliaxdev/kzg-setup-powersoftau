use std::{
    fs::File,
    io::{self, BufReader, Read},
};

use pairing::{
    bls12_381::{G1Uncompressed, G2Uncompressed},
    EncodedPoint,
};

use ark_bls12_381::Bls12_381;
use ark_poly_commit::kzg10::Powers;

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, SerializationError};
type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;

fn read_g1(reader: &mut BufReader<File>) -> Result<ArkG1Affine, SerializationError> {
    let mut repr = G1Uncompressed::empty();
    reader.read_exact(repr.as_mut()).unwrap(); //?;

    let repr_bytes = repr.as_mut();
    let mut repr_bytes_vec: Vec<u8> = vec![];
    repr_bytes_vec.extend_from_slice(&repr_bytes[000..=095]);

    repr_bytes_vec[000..=047].reverse();
    repr_bytes_vec[048..=095].reverse();

    let repr_new = ArkG1Affine::deserialize_uncompressed(&repr_bytes_vec[..]);
    repr_new
}

fn read_g2(reader: &mut BufReader<File>) -> Result<ArkG2Affine, SerializationError> {
    let mut repr = G2Uncompressed::empty();
    reader.read_exact(repr.as_mut()).unwrap(); //?;

    let repr_bytes = repr.as_mut();
    let mut repr_bytes_vec: Vec<u8> = vec![];

    /* 2 */
    repr_bytes_vec.extend_from_slice(&repr_bytes[048..=095]);
    /* 1 */
    repr_bytes_vec.extend_from_slice(&repr_bytes[000..=047]);

    /* 4 */
    repr_bytes_vec.extend_from_slice(&repr_bytes[144..=191]);
    /* 3 */
    repr_bytes_vec.extend_from_slice(&repr_bytes[096..=143]);

    repr_bytes_vec[000..=047].reverse();
    repr_bytes_vec[048..=095].reverse();
    repr_bytes_vec[096..=143].reverse();
    repr_bytes_vec[144..=191].reverse();

    let repr_new = ArkG2Affine::deserialize_uncompressed(&repr_bytes_vec[..]);
    repr_new
}

#[derive(Debug)]
struct Phase1Parameters {
    alpha: ArkG1Affine,
    beta_g1: ArkG1Affine,
    beta_g2: ArkG2Affine,
    coeffs_g1: Vec<ArkG1Affine>,
    coeffs_g2: Vec<ArkG2Affine>,
    alpha_coeffs_g1: Vec<ArkG1Affine>,
    beta_coeffs_g1: Vec<ArkG1Affine>,
}

fn load_phase1(exp: u32) -> io::Result<Phase1Parameters> {
    let m = 2_usize.pow(exp);
    println!("exp = {:?}", exp);
    println!("m = {:?}", m);
    let f = match File::open(format!("phase1radix2m{}", exp)) {
        Ok(f) => f,
        Err(e) => {
            panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
        }
    };
    let f = &mut BufReader::with_capacity(1024 * 1024, f);

    let alpha = read_g1(f).unwrap(); //?;
    let beta_g1 = read_g1(f).unwrap(); //?;
    let beta_g2 = read_g2(f).unwrap(); //?;
    let mut coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g1.push(read_g1(f).unwrap()); //?);
    }
    let mut coeffs_g2 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g2.push(read_g2(f).unwrap()); //?);
    }
    let mut alpha_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        alpha_coeffs_g1.push(read_g1(f).unwrap()); //?);
    }
    let mut beta_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        beta_coeffs_g1.push(read_g1(f).unwrap()); //?);
    }

    Ok(Phase1Parameters {
        alpha: alpha,
        beta_g1: beta_g1,
        beta_g2: beta_g2,
        coeffs_g1: coeffs_g1,
        coeffs_g2: coeffs_g2,
        alpha_coeffs_g1: alpha_coeffs_g1,
        beta_coeffs_g1: beta_coeffs_g1,
    })
}

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let exp = args[1].parse::<u32>().unwrap();

    // Download
    let phase1 = load_phase1(exp).unwrap();

    let powers_from_zcash = Powers::<Bls12_381> {
        powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
    };

    // // Checking if generators match
    // println!("powersoftau g1 generator: {:?}", phase1.coeffs_g1[0]);
    // println!("powersoftau g2 generator: {:?}", phase1.coeffs_g2[0]);
    // use ark_ec::ProjectiveCurve;
    // println!("arkwors g1 generator {:?}", ark_bls12_381::G1Projective::prime_subgroup_generator());
    // println!("arkwors g2 generator {:?}", ark_bls12_381::G2Projective::prime_subgroup_generator());
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ark_bls12_381::Fr;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use ark_poly_commit::kzg10::{Commitment, Powers, KZG10};
    use ark_poly_commit::PCCommitment;
    use ark_poly_commit::UVPolynomial;
    use ark_std::test_rng;

    #[test]
    fn completeness_test() {
        let phase1 = load_phase1(4).unwrap();

        let powers_from_zcash = Powers::<Bls12_381> {
            powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
        };

        let rng = &mut test_rng();
        let p = DensePoly::from_coefficients_slice(&[
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
            Fr::rand(rng),
        ]);
        let f = Fr::rand(rng);
        let mut f_p = DensePoly::zero();
        f_p += (f, &p);
        let hiding_bound = None;

        let (comm, _) = KZG10::commit(&powers_from_zcash, &p, hiding_bound, Some(rng)).unwrap();
        let (f_comm, _) = KZG10::commit(&powers_from_zcash, &f_p, hiding_bound, Some(rng)).unwrap();
        let mut f_comm_2 = Commitment::empty();
        f_comm_2 += (f, &comm);

        assert_eq!(f_comm, f_comm_2);
    }
}
