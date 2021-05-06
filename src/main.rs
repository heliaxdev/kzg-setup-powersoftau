use std::{fs::{
        File
    }, io::{self, BufReader, BufWriter, Read, Write}, sync::{
        Arc
    }};

use pairing::{
    EncodedPoint,
    CurveAffine,
    bls12_381::{
        G1Affine,
        G1Uncompressed,
        G2Affine,
        G2Uncompressed
    }
};

use ark_ec::PairingEngine;
use ark_serialize::CanonicalDeserialize;
type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;

fn read_g1(reader: &mut BufReader<File>) -> io::Result<G1Affine> {
    let mut repr = G1Uncompressed::empty();
    reader.read_exact(repr.as_mut())?;

    println!("repr(g1): {:?}", repr);
    
    let repr_bytes = repr.as_mut();
    let mut repr_bytes_vec:Vec<u8> = vec![];
    repr_bytes_vec.extend_from_slice(&repr_bytes[000..=095]);

    repr_bytes_vec[000..=047].reverse();
    repr_bytes_vec[048..=095].reverse();

    println!("repr_bytes(g1): {:?}", repr_bytes_vec);
    let repr_new = ArkG1Affine::deserialize_uncompressed(&repr_bytes_vec[..]);
    println!("repr_new(g1): {:?}", repr_new);

    repr.into_affine_unchecked()
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    .and_then(|e| if e.is_zero() {
        Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
    } else {
        Ok(e)
    })
}

fn read_g2(reader: &mut BufReader<File>) -> io::Result<G2Affine> {
    let mut repr = G2Uncompressed::empty();
    reader.read_exact(repr.as_mut())?;

    println!("repr(g2): {:?}", repr);

    let repr_bytes = repr.as_mut();
    let mut repr_bytes_vec:Vec<u8> = vec![];

    // repr_bytes_vec.extend_from_slice(&repr_bytes[000..=0191]);

    // repr_bytes_vec.extend_from_slice(&repr_bytes[096..=191]);
    // repr_bytes_vec.extend_from_slice(&repr_bytes[000..=095]);

    /* 2 */ repr_bytes_vec.extend_from_slice(&repr_bytes[048..=095]);
    /* 1 */ repr_bytes_vec.extend_from_slice(&repr_bytes[000..=047]);

    /* 4 */ repr_bytes_vec.extend_from_slice(&repr_bytes[144..=191]);
    /* 3 */ repr_bytes_vec.extend_from_slice(&repr_bytes[096..=143]);

    repr_bytes_vec[000..=047].reverse();
    repr_bytes_vec[048..=095].reverse();
    repr_bytes_vec[096..=143].reverse();
    repr_bytes_vec[144..=191].reverse();

    println!("repr_bytes(g2): {:?}", repr_bytes_vec);
    let repr_new = ArkG2Affine::deserialize_uncompressed(&repr_bytes_vec[..]);
    println!("repr_new(g2): {:?}\n", repr_new);

    repr.into_affine_unchecked()
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    .and_then(|e| if e.is_zero() {
        Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
    } else {
        Ok(e)
    })
}

#[derive(Debug)]
struct Phase1Parameters{
    alpha: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    coeffs_g1: Vec<G1Affine>,
    coeffs_g2: Vec<G2Affine>,
    alpha_coeffs_g1: Vec<G1Affine>,
    beta_coeffs_g1: Vec<G1Affine>
}

fn load_phase1(exp: u32) -> io::Result<Phase1Parameters>
{
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


    println!("readin alpha ========================================================================");
    let alpha = read_g1(f)?;
    println!("*************************************************************************************\n");

    println!("readin beta_g1 ======================================================================");
    let beta_g1 = read_g1(f)?;
    println!("*************************************************************************************\n");

    println!("readin beta_g2 ======================================================================");
    let beta_g2 = read_g2(f)?;
    println!("*************************************************************************************\n");

    println!("readin coeffs_g1 ======================================================================");
    let mut coeffs_g1 = Vec::with_capacity(m);
    for i in 0..m {
        println!("i = {:?}", i);
        coeffs_g1.push(read_g1(f)?);
    }
    println!("***********************************************************************************\n");

    println!("readin coeffs_g2 ======================================================================");
    let mut coeffs_g2 = Vec::with_capacity(m);
    for i in 0..m {
        println!("i = {:?}", i);
        coeffs_g2.push(read_g2(f)?);
    }
    println!("***********************************************************************************\n");

    // println!("readin alpha_coeffs_g1 ======================================================================");
    let mut alpha_coeffs_g1 = Vec::with_capacity(m);
    for i in 0..m {
        println!("i = {:?}", i);
        alpha_coeffs_g1.push(read_g1(f)?);
    }
    println!("***********************************************************************************\n");

    // println!("readin beta_coeffs_g1 ======================================================================");
    let mut beta_coeffs_g1 = Vec::with_capacity(m);
    for i in 0..m {
        println!("i = {:?}", i);
        beta_coeffs_g1.push(read_g1(f)?);
    }
    println!("***********************************************************************************\n");

    Ok(Phase1Parameters{
        alpha: alpha,
        beta_g1: beta_g1,
        beta_g2: beta_g2,
        coeffs_g1: coeffs_g1,
        coeffs_g2: coeffs_g2,
        alpha_coeffs_g1: alpha_coeffs_g1,
        beta_coeffs_g1: beta_coeffs_g1
    })
}

fn main() {
    let phase1 = load_phase1(4);
    println!("phase1: {:?}", phase1);

    // let powers_from_zcash = Powers::<Bls12_381> {
    //     powers_of_g: ark_std::borrow::Cow::Owned(phase1.unwrap().coeffs_g1.to_vec()),
    //     powers_of_gamma_g: ark_std::borrow::Cow::Owned(phase1.alpha_coeffs_g1),
    // };

    // let hiding_bound = None;
	// let (comm, _) = KZG10::commit(&powers_from_zcash, &p, hiding_bound, Some(rng)).unwrap();
	// let (f_comm, _) = KZG10::commit(&powers_from_zcash, &f_p, hiding_bound, Some(rng)).unwrap();
	// let mut f_comm_2 = Commitment::empty();
	// f_comm_2 += (f, &comm);

    // assert_eq!(f_comm, f_comm_2);

    // Checking if generators match
    // println!("powersoftau g1 generator: {:?}", phase1.coeffs_g1[0]);
    // println!("powersoftau g2 generator: {:?}", phase1.coeffs_g2[0]);
    // use ark_ec::ProjectiveCurve;
    // println!("arkwors g1 generator {:?}", ark_bls12_381::G1Projective::prime_subgroup_generator());
    // println!("arkwors g2 generator {:?}", ark_bls12_381::G2Projective::prime_subgroup_generator());  
}