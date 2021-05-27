use std::{fs::{File, OpenOptions}, io::{self, BufReader, BufWriter, Read}};
use pairing::{
    bls12_381::{G1Uncompressed, G2Uncompressed},
    EncodedPoint,
};
use ark_bls12_381::Bls12_381;
use ark_poly_commit::kzg10::{Powers, VerifierKey};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;
type ArkG1Prepared = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Prepared;
type ArkG2Prepared = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Prepared;
type ArkFqk = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fqk;
use minreq;
use std::env;
use pairing::{
    Engine,
    PrimeField,
    Field,
    CurveAffine,
    CurveProjective,
    Wnaf,
    bls12_381::{
        Bls12,
        Fr,
        G1,
        G2,
        G1Affine,
        G2Affine,
    }
};
use bls12_381::G1Projective;
use bls12_381::G2Projective;
use ark_ec::ProjectiveCurve;
use powersoftau::{Accumulator, UseCompression, CheckForCorrectness, HashReader,
    ACCUMULATOR_BYTE_SIZE,
    CONTRIBUTION_BYTE_SIZE, 
    DeserializationError};

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
    // let f = match File::open(format!("./my-response-uncompr-{}", exp)) {
    let f = match File::open(format!("../phase1radix2m{}", exp)) {
        Ok(f) => f,
        Err(e) => {
            panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
        }
    };
    let f = &mut BufReader::with_capacity(1024 * 1024, f);

    let alpha = read_g1(f).unwrap(); //?;
    println!("read alpha: {:?}", alpha);
    let beta_g1 = read_g1(f).unwrap(); //?;
    println!("read beta_g1: {:?}", beta_g1);
    let beta_g2 = read_g2(f).unwrap(); //?;
    println!("read beta_g2: {:?}", beta_g2);
    let mut coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g1.push(read_g1(f).unwrap()); //?);
    }
    println!("read coeffs_g1[0], sample: {:?}", coeffs_g1[0]);
    let mut coeffs_g2 = Vec::with_capacity(m);
    for _ in 0..m {
        coeffs_g2.push(read_g2(f).unwrap()); //?);
    }
    println!("read coeffs_g2[0], sample: {:?}", coeffs_g2[0]);
    let mut alpha_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        alpha_coeffs_g1.push(read_g1(f).unwrap()); //?);
    }
    println!("read alpha_coeffs_g1[0], sample: {:?}", alpha_coeffs_g1[0]);
    let mut beta_coeffs_g1 = Vec::with_capacity(m);
    for _ in 0..m {
        beta_coeffs_g1.push(read_g1(f).unwrap()); //?);
    }
    println!("read beta_coeffs_g1[0], sample: {:?}", beta_coeffs_g1[0]);

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

#[derive(Debug)]
struct PowersOfTau {
    tau_powers_g1: Vec<ArkG1Affine>,
    tau_powers_g2: Vec<ArkG2Affine>,
    alpha_tau_powers_g1: Vec<ArkG1Affine>,
    beta_tau_powers_g1: Vec<ArkG1Affine>,
    beta_g2: ArkG2Affine,
}

fn load_powersoftau_accum(exp: u32) -> io::Result<PowersOfTau> {
    let m = 2_usize.pow(exp);
    println!("exp = {:?}", exp);
    println!("m = {:?}", m);
    // let f = match File::open("./final-response-uncompr-21") {
    let f = match File::open(format!("./my-response-uncompr-{}", exp)) {
    // let f = match File::open(format!("../phase1radix2m{}", exp)) {
        Ok(f) => f,
        Err(e) => {
            panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
        }
    };
    let f = &mut BufReader::with_capacity(1024 * 1024, f);

    let TAU_POWERS_LENGTH: usize = 1 << exp;
    // let TAU_POWERS_LENGTH: usize = 1 << 21;
    let TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

    let mut tau_powers_g1 = Vec::with_capacity(TAU_POWERS_G1_LENGTH);
    for _ in 0..TAU_POWERS_G1_LENGTH {
        tau_powers_g1.push(read_g1(f).unwrap()); //?);
    }

    let mut tau_powers_g2 = Vec::with_capacity(TAU_POWERS_LENGTH);
    for _ in 0..TAU_POWERS_LENGTH {
        tau_powers_g2.push(read_g2(f).unwrap()); //?);
    }

    let mut alpha_tau_powers_g1 = Vec::with_capacity(TAU_POWERS_LENGTH);
    for _ in 0..TAU_POWERS_LENGTH {
        alpha_tau_powers_g1.push(read_g1(f).unwrap()); //?);
    }

    let mut beta_tau_powers_g1 = Vec::with_capacity(TAU_POWERS_LENGTH);
    for _ in 0..TAU_POWERS_LENGTH {
        beta_tau_powers_g1.push(read_g1(f).unwrap()); //?);
    }

    let beta_g2 = read_g2(f).unwrap(); //?;

    Ok(PowersOfTau {
        tau_powers_g1: tau_powers_g1,
        tau_powers_g2: tau_powers_g2,
        alpha_tau_powers_g1: alpha_tau_powers_g1,
        beta_tau_powers_g1: beta_tau_powers_g1,
        beta_g2: beta_g2
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let exp = args[1].parse::<u32>().unwrap();


    // let phase1 = load_phase1(exp).unwrap();
    // let powersoftau = Powers::<Bls12_381> {
    //     powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
    //     powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
    // };

    // // Checking if generators match
    // println!("powersoftau g1 generator: {:?}", phase1.coeffs_g1[0]);
    // println!("powersoftau g2 generator: {:?}", phase1.coeffs_g2[0]);
    // use ark_ec::ProjectiveCurve;
    // println!("arkwors g1 generator {:?}", ark_bls12_381::G1Affine::prime_subgroup_generator());
    // println!("arkwors g2 generator {:?}", ark_bls12_381::G2Affine::prime_subgroup_generator());

    // println!("G1Affine generator {:?}", bls12_381::G1Affine::generator());
    // println!("G2Affine generator {:?}", bls12_381::G2Affine::generator());


    // let tau_powers = load_powersoftau_accum(exp);
    // println!("tau_powers = {:?}", tau_powers);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // use powersoftau::{Accumulator, UseCompression, CheckForCorrectness, HashReader ,ACCUMULATOR_BYTE_SIZE};

    // // let ACCUMULATOR_BYTE_SIZE = 18592;
    // let reader = OpenOptions::new()
    // .read(true)
    // .open("../my-challenge-5").expect("unable open `./challenge` in this directory");

    // {
    //     let metadata = reader.metadata().expect("unable to get filesystem metadata for `./challenge`");
    //     if metadata.len() != (ACCUMULATOR_BYTE_SIZE as u64) {
    //         panic!("The size of `./challenge` should be {}, but it's {}, so something isn't right.", ACCUMULATOR_BYTE_SIZE, metadata.len());
    //     }
    // }

    // let reader = BufReader::new(reader);
    // let mut reader = HashReader::new(reader);
    // use std::fs::OpenOptions;

    // // Create `./response` in this directory
    // // let writer = OpenOptions::new()
    // //                         .read(false)
    // //                         .write(true)
    // //                         .create_new(true)
    // //                         .open("response").expect("unable to create `./response` in this directory");
    
    // println!("Reading `./challenge` into memory...");

    // // Read the BLAKE2b hash of the previous contribution
    // {   
    //     // We don't need to do anything with it, but it's important for
    //     // the hash chain.
    //     let mut tmp = [0; 64];
    //     reader.read_exact(&mut tmp).expect("unable to read BLAKE2b hash of previous contribution");
    // }   

    // // Load the current accumulator into memory
    // let mut acc = Accumulator::deserialize(&mut reader, UseCompression::No, CheckForCorrectness::No).expect("unable to read uncompressed accumulator");

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // let CONTRIBUTION_BYTE_SIZE = 603981040;
    let file = "./my-response-21";
    let file_out = "./my-response-uncompr-21";
    let exp = 21;

    // Try to load `./response` from disk.
    let response_reader = OpenOptions::new()
                            .read(true)
                            .open(file).expect("unable open `./response` in this directory");

    {
        let metadata = response_reader.metadata().expect("unable to get filesystem metadata for `./response`");
        if metadata.len() != (CONTRIBUTION_BYTE_SIZE as u64) {
            panic!("The size of `./response` should be {}, but it's {}, so something isn't right.", CONTRIBUTION_BYTE_SIZE, metadata.len());
        }
    }

    let response_reader = BufReader::new(response_reader);
    let mut response_reader = HashReader::new(response_reader);

    // Check the hash chain
    {   
        let mut response_challenge_hash = [0; 64];
        response_reader.read_exact(&mut response_challenge_hash).expect("couldn't read hash of challenge file from response file");

        // if &response_challenge_hash[..] != current_accumulator_hash.as_slice() {
        //     panic!("Hash chain failure. This is not the right response.");
        // }
    }

    let TAU_POWERS_LENGTH: usize = 1 << exp;
    let TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

    println!("Started deserializing...");
    // Load the response's accumulator
    let new_accumulator = Accumulator::deserialize(&mut response_reader, UseCompression::Yes, CheckForCorrectness::No)
                                                  .expect("wasn't able to deserialize the response file's accumulator");

    println!("Done deserializing...");
    // Create new_challenge file
    let writer = OpenOptions::new()
    .read(false)
    .write(true)
    .create_new(true)
    .open(file_out).expect("unable to create `./final-response-uncompr-21`");

    let mut writer = BufWriter::new(writer);
    println!("Started serializing...");
    new_accumulator.serialize(&mut writer, UseCompression::No)
                    .expect("wasn't able to deserialize the response file's accumulator");
    println!("Done serializing...");

}

#[cfg(test)]
mod tests {
    #![allow(non_camel_case_types)]
    use crate::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{PairingEngine};
    use ark_ff::{UniformRand};
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use ark_poly_commit::kzg10::*;
    use ark_poly_commit::Error;
    use ark_poly_commit::UVPolynomial;
    use ark_poly_commit::Polynomial;
    use ark_std::{rand::RngCore, test_rng};

    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;

    pub struct TestingParameters {}
    pub trait ThresholdEncryptionParameters {
        type E: PairingEngine;
    }  
    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    fn end_to_end_test_template() -> Result<(), Error> {     
        let exp:usize = 5;
        let phase1 = load_phase1(exp as u32).unwrap();
        println!("loaded phase1");
        let powersoftau = Powers::<Bls12_381> {
            powers_of_g: ark_std::borrow::Cow::Owned(phase1.coeffs_g1.to_vec()),
            // powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.beta_coeffs_g1),
        };

        let vk = VerifierKey {
            g: powersoftau.powers_of_g[0],
            gamma_g: powersoftau.powers_of_gamma_g[0],
            h: phase1.coeffs_g2[0],                      //pp.h,
            beta_h: phase1.coeffs_g2[1],                 //.beta_g2, //pp.beta_h,
            prepared_h: phase1.coeffs_g2[0].into(),      //pp.prepared_h.clone(),
            prepared_beta_h: phase1.coeffs_g2[1].into(), //beta_g2.into(), //pp.prepared_beta_h.clone(),
        };

        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                // degree = usize::rand(rng) % 20;
                degree = usize::rand(rng) % 10;
            }
            degree = exp;

            // let kzg_pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
            // let (kzg_ck, kzg_vk) = trim(&kzg_pp, degree)?;

            let p = UniPoly_381::rand(degree, rng);
            let hiding_bound = None;//Some(1);
            let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(
                &powersoftau,
                &p,
                hiding_bound,
                None, //Some(rng),
            )?;
            let point =
                <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof =
                KZG10::<Bls12_381, UniPoly_381>::open(&powersoftau, &p, point, &rand)?;
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

    // fn batch_check_test_template() -> Result<(), Error>
    // {
    //     let exp = 21;
    //     let params = load_powersoftau_accum(exp).unwrap();
    //     println!("loaded powersoftau");

    //     let powersoftau = Powers::<Bls12_381> {
    //         powers_of_g: ark_std::borrow::Cow::Owned(params.tau_powers_g1.to_vec()),
    //         powers_of_gamma_g: ark_std::borrow::Cow::Owned(params.alpha_tau_powers_g1.to_vec()),
    //     };

    //     let vk = VerifierKey {
    //         g: powersoftau.powers_of_g[0],
    //         gamma_g: powersoftau.powers_of_gamma_g[0],
    //         h: params.tau_powers_g2[0],                      //pp.h,
    //         beta_h: params.tau_powers_g2[1],                 //.beta_g2, //pp.beta_h,
    //         prepared_h: params.tau_powers_g2[0].into(),      //pp.prepared_h.clone(),
    //         prepared_beta_h: params.tau_powers_g2[1].into(), //beta_g2.into(), //pp.prepared_beta_h.clone(),
    //     };

    //     let rng = &mut test_rng();
    //     for _ in 0..10 {
    //         let mut degree = 0;
    //         while degree <= 1 {
    //             degree = usize::rand(rng) % 20;
    //         }
    //         // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
    //         // let (ck, vk) = trim::<E, P>(&pp, degree)?;
    //         let mut comms = Vec::new();
    //         let mut values = Vec::new();
    //         let mut points = Vec::new();
    //         let mut proofs = Vec::new();
    //         for _ in 0..10 {
    //             let p = UniPoly_381::rand(degree, rng);
    //             let hiding_bound = Some(1);
    //             let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powersoftau, &p, hiding_bound, Some(rng))?;
    //             let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
    //             let value = p.evaluate(&point);
    //             let proof = KZG10::<Bls12_381, UniPoly_381>::open(&powersoftau, &p, point, &rand)?;
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

    const POWERSOFTAU_FILE: &str= "final-response-uncompr-21";
    const TAU_POWERS_LENGTH: usize = 1 << 21;
    const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;
    fn load_powersoftau_accum() -> io::Result<PowersOfTau> {
        let f = match File::open(POWERSOFTAU_FILE) {
            Ok(f) => f,
            Err(e) => {
                panic!("Couldn't load {}. Error: {}", POWERSOFTAU_FILE, e);
            }
        };
        let f = &mut BufReader::with_capacity(1024 * 1024, f);
    
        let mut tau_powers_g1 = Vec::with_capacity(TAU_POWERS_G1_LENGTH);
        for _ in 0..TAU_POWERS_G1_LENGTH {
            tau_powers_g1.push(read_g1(f).unwrap());
        }
    
        let mut tau_powers_g2 = Vec::with_capacity(TAU_POWERS_LENGTH);
        for _ in 0..TAU_POWERS_LENGTH {
            tau_powers_g2.push(read_g2(f).unwrap());
        }
    
        let mut alpha_tau_powers_g1 = Vec::with_capacity(TAU_POWERS_LENGTH);
        for _ in 0..TAU_POWERS_LENGTH {
            alpha_tau_powers_g1.push(read_g1(f).unwrap());
        }
    
        let mut beta_tau_powers_g1 = Vec::with_capacity(TAU_POWERS_LENGTH);
        for _ in 0..TAU_POWERS_LENGTH {
            beta_tau_powers_g1.push(read_g1(f).unwrap());
        }
    
        let beta_g2 = read_g2(f).unwrap(); //?;
    
        Ok(PowersOfTau {
            tau_powers_g1: tau_powers_g1,
            tau_powers_g2: tau_powers_g2,
            alpha_tau_powers_g1: alpha_tau_powers_g1,
            beta_tau_powers_g1: beta_tau_powers_g1,
            beta_g2: beta_g2
        })
    }
    #[test]
    fn end_to_end_test_powersoftau() -> Result<(), Error> {
        const exp: usize = 21;
        const TAU_POWERS_LENGTH: usize = 1 << exp;
        const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

        // Load KZG setup params
        // let params = load_powersoftau_accum().unwrap();
        // println!("Loaded Powers of Tau");
    
        // let powersoftau = Powers::<Bls12_381> {
        //     powers_of_g: ark_std::borrow::Cow::Owned(params.tau_powers_g1.to_vec()),
        //     powers_of_gamma_g: ark_std::borrow::Cow::Owned(params.alpha_tau_powers_g1.to_vec()),
        // };
    
        // let vk: VerifierKey<Bls12_381> = VerifierKey {
        //     g: powersoftau.powers_of_g[0],
        //     gamma_g: powersoftau.powers_of_gamma_g[0],
        //     h: params.tau_powers_g2[0],
        //     beta_h: params.tau_powers_g2[1],
        //     prepared_h: params.tau_powers_g2[0].into(),
        //     prepared_beta_h: params.tau_powers_g2[1].into(),
        // };

        let reader = File::open(format!("kzg_setup-{}", exp)).unwrap();    
        let mut reader = BufReader::new(reader);
        let mut powers_of_g = Vec::<ArkG1Affine>::with_capacity(TAU_POWERS_G1_LENGTH);
        let mut powers_of_gamma_g = Vec::<ArkG1Affine>::with_capacity(TAU_POWERS_LENGTH);
        for _ in 0..TAU_POWERS_G1_LENGTH {
            powers_of_g.push(ArkG1Affine::deserialize_unchecked(&mut reader).unwrap());
        }
        for _ in 0..TAU_POWERS_LENGTH {
            powers_of_gamma_g.push(ArkG1Affine::deserialize_unchecked(&mut reader).unwrap());
        }

        let powersoftau = Powers::<Bls12_381> {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        let vk: VerifierKey<Bls12_381> = VerifierKey::<Bls12_381>::deserialize_unchecked(reader).unwrap();

        // let params = load_powersoftau_accum(exp as u32).unwrap();
        // println!("loaded powersoftau");
        // let powersoftau = Powers::<Bls12_381> {
        //     powers_of_g: ark_std::borrow::Cow::Owned(params.tau_powers_g1.to_vec()),
        //     powers_of_gamma_g: ark_std::borrow::Cow::Owned(params.alpha_tau_powers_g1.to_vec()),
        // };

        // let vk = VerifierKey {
        //     g: powersoftau.powers_of_g[0],
        //     gamma_g: powersoftau.powers_of_gamma_g[0],
        //     h: params.tau_powers_g2[0],
        //     beta_h: params.tau_powers_g2[1],
        //     prepared_h: params.tau_powers_g2[0].into(),
        //     prepared_beta_h: params.tau_powers_g2[1].into(),
        // };

        // let rng = &mut test_rng();
        // // for _ in 0..100 {
        //     let mut degree = 0;
        //     while degree <= 1 {
        //         // degree = usize::rand(rng) % 20;
        //         degree = usize::rand(rng) % 10;
        //     }
        //     /* todo remove: */ degree = exp as usize;

        //     let p = UniPoly_381::rand(degree, rng);
        //     let hiding_bound = Some(1);
        //     let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(
        //         &powersoftau,
        //         &p,
        //         hiding_bound,
        //         Some(rng),
        //     )?;
        //     let point =
        //         <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
        //     let value = p.evaluate(&point);
        //     let proof =
        //         KZG10::<Bls12_381, UniPoly_381>::open(&powersoftau, &p, point, &rand)?;
        //     assert!(
        //         KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?,
        //         "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
        //         degree,
        //         p.degree(),
        //         hiding_bound,
        //     );
        // // }

        // let buffer = File::create(format!("kzg_setup-{}", exp)).unwrap();
        // println!("g:");
        // for g in powersoftau.powers_of_g.iter() {
        //     println!("{:?}", g);
        //     g.serialize_uncompressed(&buffer).unwrap();
        // }
        // println!("gamma_g:");
        // for g in powersoftau.powers_of_gamma_g.iter() {
        //     println!("{:?}", g);
        //     g.serialize_uncompressed(&buffer).unwrap();
        // }
        // println!("vk = {:?}", vk);

        // vk.serialize_uncompressed(buffer).unwrap();

        Ok(())
    }

    // #[test]
    // fn end_to_end_test() {
    //    // end_to_end_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
        // end_to_end_test_template().expect("test failed for bls12-381");
    // }

    // #[test]
    // fn batch_check_test() {
    //     // batch_check_test_template::<Bls12_377, UniPoly_377>().expect("test failed for bls12-377");
    //     batch_check_test_template().expect("test failed for bls12-381");
    // }
}
