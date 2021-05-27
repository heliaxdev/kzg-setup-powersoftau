use std::{fs::File, io::{self, BufReader, Read}};
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use pairing::{
    bls12_381::{G1Uncompressed, G2Uncompressed},
    EncodedPoint,
};
use ark_poly_commit::kzg10::{Powers, VerifierKey};

type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;

const POWERSOFTAU_FILE: &str = "powersoftau";
const PARAMS_FILE: &str = "kzg_setup";
const TAU_POWERS_LENGTH: usize = 1 << 21;
const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

struct PowersOfTau {
    tau_powers_g1: Vec<ArkG1Affine>,
    tau_powers_g2: Vec<ArkG2Affine>,
    alpha_tau_powers_g1: Vec<ArkG1Affine>,
    beta_tau_powers_g1: Vec<ArkG1Affine>,
    beta_g2: ArkG2Affine,
}

pub fn download_parameters() -> Result<(), minreq::Error> {
    const DOWNLOAD_URL: &str = "https://powersoftau-transcript.s3-us-west-2.amazonaws.com/88dc1dc6914e44568e8511eace177e6ecd9da9a9bd8f67e4c0c9f215b517db4d1d54a755d051978dbb85ef947918193c93cd4cf4c99c0dc5a767d4eeb10047a4";

    let fetch_params = |expected_hash: &str| -> Result<(), minreq::Error> {
        use std::io::Write;

        let part_1 = minreq::get(DOWNLOAD_URL).send()?;

        // TODO
        // // Verify parameter file hash.
        // let hash = blake2b_simd::State::new()
        //     .update(part_1.as_bytes())
        //     .finalize()
        //     .to_hex();
        // if &hash != expected_hash {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidData,
        //         format!(
        //             "{} failed validation (expected: {}, actual: {}, fetched {} bytes)",
        //             exp,
        //             expected_hash,
        //             hash,
        //             part_1.as_bytes().len()
        //         ),
        //     )
        //     .into());
        // }

        // Write parameter file.
        let mut f = File::create(POWERSOFTAU_FILE)?;
        f.write_all(part_1.as_bytes())?;
        Ok(())
    };

    fetch_params("")?;

    Ok(())
}

fn read_g1(reader: &mut BufReader<File>) -> Result<ArkG1Affine, SerializationError> {
    let mut repr = G1Uncompressed::empty();
    reader.read_exact(repr.as_mut()).unwrap();

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
    reader.read_exact(repr.as_mut()).unwrap();

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

fn main() {
    // download_parameters().unwrap();
    println!("Downloaded Powers of Tau");

    let params = load_powersoftau_accum().unwrap();
    println!("Loaded Powers of Tau");

    let powersoftau = Powers::<Bls12_381> {
        powers_of_g: ark_std::borrow::Cow::Owned(params.tau_powers_g1.to_vec()),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(params.alpha_tau_powers_g1.to_vec()),
    };

    let vk: VerifierKey<Bls12_381> = VerifierKey {
        g: powersoftau.powers_of_g[0],
        gamma_g: powersoftau.powers_of_gamma_g[0],
        h: params.tau_powers_g2[0],
        beta_h: params.tau_powers_g2[1],
        prepared_h: params.tau_powers_g2[0].into(),
        prepared_beta_h: params.tau_powers_g2[1].into(),
    };

    let buffer = File::create(PARAMS_FILE).unwrap();
    for g in powersoftau.powers_of_g.iter() {
        g.serialize_uncompressed(&buffer).unwrap();
    }
    for g in powersoftau.powers_of_gamma_g.iter() {
        g.serialize_uncompressed(&buffer).unwrap();
    }
    vk.serialize_uncompressed(buffer).unwrap();
}