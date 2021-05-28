use ark_std::rand;
use std::{fs::{File, OpenOptions}, io::{self, BufReader, BufWriter, Read}, path::Path};
use pairing::{
    bls12_381::{G1Uncompressed, G2Uncompressed},
    EncodedPoint,
};
use ark_bls12_381::Bls12_381;
use ark_poly_commit::kzg10::{Powers, VerifierKey};
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Write};
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

type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;
type ArkG1Prepared = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Prepared;
type ArkG2Prepared = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Prepared;

pub const KGZ_SETUP_FILE: &str = "kzg_setup";
const KGZ_SETUP_FILE_DIGEST: &str = "87932f626204ab9a5d4be67ef2ee479471baf942364ada2f89840a2afec8925911fb88cb77024e66d759b4970b25cf2a7b03d1fc8c15768e021220b8ba21efcf";
const TAU_POWERS_LENGTH: usize = 1 << 21;
const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;
const KGZ_SETUP_URL:&str = "https://heliax-ferveo-v1.s3-eu-west-1.amazonaws.com/ferveo-dkg-kzg-setup";

#[derive(Debug)]
pub struct Phase1Parameters {
    alpha: ArkG1Affine,
    beta_g1: ArkG1Affine,
    beta_g2: ArkG2Affine,
    coeffs_g1: Vec<ArkG1Affine>,
    coeffs_g2: Vec<ArkG2Affine>,
    alpha_coeffs_g1: Vec<ArkG1Affine>,
    beta_coeffs_g1: Vec<ArkG1Affine>,
}

pub fn read_g1(reader: &mut BufReader<File>) -> Result<ArkG1Affine, SerializationError> {
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

pub fn read_g2(reader: &mut BufReader<File>) -> Result<ArkG2Affine, SerializationError> {
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

pub fn load_phase1(exp: u32) -> io::Result<Phase1Parameters> {
    let m = 2_usize.pow(exp);
    let f = match File::open(format!("../phase1radix2m{}", exp)) {
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

pub fn download_kzg_setup() -> Result<(), minreq::Error> {
    fn check_file_hash(data: &[u8]) -> bool {
        let hash = blake2b_simd::State::new()
        .update(data)
        .finalize()
        .to_hex();
        &hash == KGZ_SETUP_FILE_DIGEST
    }

    if Path::new(KGZ_SETUP_FILE).exists() {
        println!("Checking existing {} file...", KGZ_SETUP_FILE);
        let mut f = File::open(KGZ_SETUP_FILE)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        if check_file_hash(&buffer) {
            println!("Checking passed, using existing {} file.", KGZ_SETUP_FILE);
            return Ok(());
        }
    }

    println!("Downloading {}", KGZ_SETUP_URL);
    let powersoftau = minreq::get(KGZ_SETUP_URL).send()?;
    if !check_file_hash(powersoftau.as_bytes()) {
        return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed validation (expected: {}, fetched {} bytes)",
                        KGZ_SETUP_FILE_DIGEST,
                        powersoftau.as_bytes().len()
                    ),
                )
                .into());
    }

    // Write parameter file.
    let mut f = File::create(KGZ_SETUP_FILE)?;
    f.write_all(powersoftau.as_bytes())?;
    return Ok(());
}

pub fn load_kzg_setup<'a>() -> (Powers<'a, Bls12_381>, VerifierKey<Bls12_381>) {
    let reader = File::open(KGZ_SETUP_FILE).unwrap();    
    let mut reader = BufReader::new(reader);
    let mut powers_of_g = Vec::<ArkG1Affine>::with_capacity(TAU_POWERS_G1_LENGTH);
    let mut powers_of_gamma_g = Vec::<ArkG1Affine>::with_capacity(TAU_POWERS_LENGTH);
    for _ in 0..TAU_POWERS_G1_LENGTH {
        powers_of_g.push(ArkG1Affine::deserialize_unchecked(&mut reader).unwrap());
    }
    for _ in 0..TAU_POWERS_LENGTH {
        powers_of_gamma_g.push(ArkG1Affine::deserialize_unchecked(&mut reader).unwrap());
    }

    let powers = Powers::<Bls12_381> {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    let vk: VerifierKey<Bls12_381> = VerifierKey::<Bls12_381>::deserialize_unchecked(reader).unwrap();

    (powers, vk)
}

mod tests{
    use std::{fs::File, io::BufReader};
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_poly_commit::{Error, kzg10::{KZG10, Powers}, Polynomial};
    use ark_poly_commit::PCVerifierKey;
    use ark_std::test_rng;
    use crate::{ArkG1Affine, load_kzg_setup};
    use ark_serialize::{CanonicalDeserialize};
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use crate::*;
    use ark_poly_commit::kzg10::*;
    use ark_serialize::{CanonicalSerialize, SerializationError};
    use ark_std::UniformRand;
    use ark_poly_commit::UVPolynomial;

    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;

#[test]
    fn end_to_end_test_powersoftau() -> Result<(), Error> {
        let (powers, vk) = load_kzg_setup();

        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();
            for _ in 0..10 {
                let p = UniPoly_381::rand(degree, rng);
                let hiding_bound = Some(1);
                let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &p, hiding_bound, Some(rng))?;
                let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
                let value = p.evaluate(&point);
                let proof = KZG10::<Bls12_381, UniPoly_381>::open(&powers, &p, point, &rand)?;
                assert!(KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?);
                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }
            assert!(KZG10::<Bls12_381, UniPoly_381>::batch_check(
                &vk, &comms, &points, &values, &proofs, rng
            )?);
        }
        Ok(())
    }

    #[test]
    fn batch_check_test_template() -> Result<(), Error>
    {
        let (powers, vk) = load_kzg_setup();

        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();
            for _ in 0..10 {
                let p = UniPoly_381::rand(degree, rng);
                let hiding_bound = Some(1);
                let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &p, hiding_bound, Some(rng))?;
                let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
                let value = p.evaluate(&point);
                let proof = KZG10::<Bls12_381, UniPoly_381>::open(&powers, &p, point, &rand)?;
                assert!(KZG10::<Bls12_381, UniPoly_381>::check(&vk, &comm, point, value, &proof)?);
                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }
            assert!(KZG10::<Bls12_381, UniPoly_381>::batch_check(
                &vk, &comms, &points, &values, &proofs, rng
            )?);
        }
        Ok(())
    }
}