// use ark_ec::PairingEngine;
// type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
// type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;


// #[derive(Debug)]
// struct PowersOfTau {
//     tau_powers_g1: Vec<ArkG1Affine>,
//     tau_powers_g2: Vec<ArkG2Affine>,
//     alpha_tau_powers_g1: Vec<ArkG1Affine>,
//     beta_tau_powers_g1: Vec<ArkG1Affine>,
//     beta_g2: ArkG2Affine,
// }

fn main() {}

// #[cfg(test)]
// mod tests {
//     #![allow(non_camel_case_types)]
//     use std::fs::File;
//     use std::io::BufReader;

//     use crate::*;
//     use ark_bls12_381::Bls12_381;
//     use ark_ec::{PairingEngine};
//     use ark_poly::univariate::DensePolynomial as DensePoly;
//     use ark_poly_commit::kzg10::*;
//     use ark_poly_commit::Error;
//     use ark_std::test_rng;
//     use trusted_setup::KGZ_SETUP_FILE;
//     use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

//     type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;

//     pub struct TestingParameters {}
//     pub trait ThresholdEncryptionParameters {
//         type E: PairingEngine;
//     }  
//     impl ThresholdEncryptionParameters for TestingParameters {
//         type E = ark_bls12_381::Bls12_381;
//     }

//     fn batch_check_test_template() -> Result<(), Error>
//     {
//         let exp = 21;
//         let params = load_powersoftau_accum(exp).unwrap();
//         println!("loaded powersoftau");

//         let powersoftau = Powers::<Bls12_381> {
//             powers_of_g: ark_std::borrow::Cow::Owned(params.tau_powers_g1.to_vec()),
//             powers_of_gamma_g: ark_std::borrow::Cow::Owned(params.alpha_tau_powers_g1.to_vec()),
//         };

//         let vk = VerifierKey {
//             g: powersoftau.powers_of_g[0],
//             gamma_g: powersoftau.powers_of_gamma_g[0],
//             h: params.tau_powers_g2[0],                      //pp.h,
//             beta_h: params.tau_powers_g2[1],                 //.beta_g2, //pp.beta_h,
//             prepared_h: params.tau_powers_g2[0].into(),      //pp.prepared_h.clone(),
//             prepared_beta_h: params.tau_powers_g2[1].into(), //beta_g2.into(), //pp.prepared_beta_h.clone(),
//         };

//         let rng = &mut test_rng();
//         for _ in 0..10 {
//             let mut degree = 0;
//             while degree <= 1 {
//                 degree = usize::rand(rng) % 20;
//             }
//             // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
//             // let (ck, vk) = trim::<E, P>(&pp, degree)?;
//             let mut comms = Vec::new();
//             let mut values = Vec::new();
//             let mut points = Vec::new();
//             let mut proofs = Vec::new();
//             for _ in 0..10 {
//                 let p = UniPoly_381::rand(degree, rng);
//                 let hiding_bound = Some(1);
//                 let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powersoftau, &p, hiding_bound, Some(rng))?;
//                 let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
//                 let value = p.evaluate(&point);
//                 let proof = KZG10::<Bls12_381, UniPoly_381>::open(&powersoftau, &p, point, &rand)?;
//                 assert!(KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?);
//                 comms.push(comm);
//                 values.push(value);
//                 points.push(point);
//                 proofs.push(proof);
//             }
//             assert!(KZG10::<Bls12_381, UniPoly_381>::batch_check(
//                 &vk, &comms, &points, &values, &proofs, rng
//             )?);
//         }
//         Ok(())
//     }

// }
