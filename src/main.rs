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
    #![allow(non_camel_case_types)]
    use crate::*;
    // use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::PairingEngine;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use ark_poly_commit::kzg10::*; //{Commitment, Powers, KZG10};
    use ark_poly_commit::Error;
    use ark_poly_commit::PCCommitment;
    use ark_poly_commit::UVPolynomial;
    // use ark_std::ops::Div;
    use ark_std::test_rng;
    use ark_poly_commit::Polynomial;

    use ark_ec::bls12::G1Projective;
    use ark_ec::ProjectiveCurve;

    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;
    // type UniPoly_377 = DensePoly<<Bls12_377 as PairingEngine>::Fr>;

    // impl<E: PairingEngine, P: UVPolynomial<E::Fr>> KZG10<E, P> {
    /// Specializes the public parameters for a given maximum degree `d` for polynomials
    /// `d` should be less that `pp.max_degree()`.
    fn trim(
        pp: &UniversalParams<Bls12_381>,
        mut supported_degree: usize,
    ) -> Result<(Powers<Bls12_381>, VerifierKey<Bls12_381>), Error> {
        if supported_degree == 1 {
            supported_degree += 1;
        }
        let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
        let powers_of_gamma_g = (0..=supported_degree)
            .map(|i| pp.powers_of_gamma_g[&i])
            .collect();

        let powers = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        Ok((powers, vk))
    }

    #[test]
    fn add_commitments_test() {
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

    fn end_to_end_test_template() -> Result<(), Error>
    {
        let phase1 = load_phase1(10).unwrap();
        println!("loaded phase1");
        let powers_from_zcash = Powers::<Bls12_381> {
            powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
        };

        let vk = VerifierKey {
            g: powers_from_zcash.powers_of_g[0],
            gamma_g: powers_from_zcash.powers_of_gamma_g[0],
            h: phase1.coeffs_g2[1], //pp.h,
            beta_h: phase1.coeffs_g2[2], //.beta_g2, //pp.beta_h,
            prepared_h: phase1.coeffs_g2[0].into(), //pp.prepared_h.clone(),
            prepared_beta_h: phase1.coeffs_g2[1].into() //beta_g2.into(), //pp.prepared_beta_h.clone(),
        };

        // struct Phase1Parameters {
        //     alpha: ArkG1Affine,
        //     beta_g1: ArkG1Affine,
        //     beta_g2: ArkG2Affine,
        //     coeffs_g1: Vec<ArkG1Affine>,
        //     coeffs_g2: Vec<ArkG2Affine>,
        //     alpha_coeffs_g1: Vec<ArkG1Affine>,
        //     beta_coeffs_g1: Vec<ArkG1Affine>,
        // }

        // Ok(Phase1Parameters {
        //     alpha: alpha,
        //     beta_g1: beta_g1,
        //     beta_g2: beta_g2,
        //     coeffs_g1: coeffs_g1,
        //     coeffs_g2: coeffs_g2,
        //     alpha_coeffs_g1: alpha_coeffs_g1,
        //     beta_coeffs_g1: beta_coeffs_g1,
        // });

        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                // degree = usize::rand(rng) % 20;
                degree = usize::rand(rng) % 10;
            }
            println!("degree = {:?}", degree);

            // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
            // let (ck, vk) = trim(&pp, degree)?;
            let p = UniPoly_381::rand(degree, rng);
            let hiding_bound = Some(1);
            let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers_from_zcash, &p, hiding_bound, Some(rng))?;
            let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof = KZG10::<Bls12_381, UniPoly_381>::open(&powers_from_zcash, &p, point, &rand)?;
            assert!(
                KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
                degree,
                p.degree(),
                hiding_bound,
            );
        }
        Ok(())
    }

    // fn linear_polynomial_test_template<E, P>() -> Result<(), Error>
    // where
    //     E: PairingEngine,
    //     P: UVPolynomial<E::Fr, Point = E::Fr>,
    //     for<'a, 'b> &'a P: Div<&'b P, Output = P>,
    // {
    //     let phase1 = load_phase1(4).unwrap();
    //     let powers_from_zcash = Powers::<Bls12_381> {
    //         powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
    //         powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
    //     };
    
    //     let rng = &mut test_rng();
    //     for _ in 0..100 {
    //         let degree = 50;
    //         let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
    //         let (ck, vk) = trim::<E, P>(&pp, 2)?;
    //         let p = P::rand(1, rng);
    //         let hiding_bound = Some(1);
    //         let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&ck, &p, hiding_bound, Some(rng))?;
    //         let point = E::Fr::rand(rng);
    //         let value = p.evaluate(&point);
    //         let proof = KZG10::<Bls12_381, UniPoly_381>::open(&ck, &p, point, &rand)?;
    //         assert!(
    //             KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?,
    //             "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
    //             degree,
    //             p.degree(),
    //             hiding_bound,
    //         );
    //     }
    //     Ok(())
    // }

    // fn batch_check_test_template<E, P>() -> Result<(), Error>
    // where
    //     E: PairingEngine,
    //     P: UVPolynomial<E::Fr, Point = E::Fr>,
    //     for<'a, 'b> &'a P: Div<&'b P, Output = P>,
    // {
    //     let phase1 = load_phase1(4).unwrap();
    //     let powers_from_zcash = Powers::<Bls12_381> {
    //         powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
    //         powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
    //     };

    //     let rng = &mut test_rng();
    //     for _ in 0..10 {
    //         let mut degree = 0;
    //         while degree <= 1 {
    //             degree = usize::rand(rng) % 20;
    //         }
    //         let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
    //         let (ck, vk) = trim::<E, P>(&pp, degree)?;
    //         let mut comms = Vec::new();
    //         let mut values = Vec::new();
    //         let mut points = Vec::new();
    //         let mut proofs = Vec::new();
    //         for _ in 0..10 {
    //             let p = P::rand(degree, rng);
    //             let hiding_bound = Some(1);
    //             let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&ck, &p, hiding_bound, Some(rng))?;
    //             let point = E::Fr::rand(rng);
    //             let value = p.evaluate(&point);
    //             let proof = KZG10::<Bls12_381, UniPoly_381>::open(&ck, &p, point, &rand)?;

    //             assert!(KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?);
    //             comms.push(comm);
    //             values.push(value);
    //             points.push(point);
    //             proofs.push(proof);
    //         }
    //         assert!(KZG10::<Bls12_381, UniPoly_381>::batch_check(
    //             &vk, &comms, &points, &values, &proofs, rng
    //         )?);
    //     }
    //     Ok(())
    // }

    #[test]
    fn end_to_end_test() {
        // end_to_end_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
        end_to_end_test_template().expect("test failed for bls12-381");
    }

    // #[test]
    // fn linear_polynomial_test() {
    //     // linear_polynomial_test_template::<Bls12_377, UniPoly_377>()
    //         // .expect("test failed for bls12-377");
    //     linear_polynomial_test_template::<Bls12_381, UniPoly_381>()
    //         .expect("test failed for bls12-381");
    // }
    // #[test]
    // fn batch_check_test() {
    //     // batch_check_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
    //     batch_check_test_template::<Bls12_381, UniPoly_381>().expect("test failed for bls12-381");
    // }
}
