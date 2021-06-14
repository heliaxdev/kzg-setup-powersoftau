use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_poly_commit::kzg10::{Powers, VerifierKey};
use ark_serialize::CanonicalSerialize;
use powersoftau::{
    Accumulator, CheckForCorrectness, HashReader, UseCompression, CONTRIBUTION_BYTE_SIZE,
};
use std::io::Write;
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read},
};
use kzg_setup_powersoftau::{read_g1, read_g2, KZG_SETUP_FILE};

type ArkG1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type ArkG2Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;

const DOWNLOAD_URL: &str = "https://powersoftau-transcript.s3-us-west-2.amazonaws.com/88dc1dc6914e44568e8511eace177e6ecd9da9a9bd8f67e4c0c9f215b517db4d1d54a755d051978dbb85ef947918193c93cd4cf4c99c0dc5a767d4eeb10047a4";
const POWERSOFTAU_DIGEST: &str = "88dc1dc6914e44568e8511eace177e6ecd9da9a9bd8f67e4c0c9f215b517db4d1d54a755d051978dbb85ef947918193c93cd4cf4c99c0dc5a767d4eeb10047a4";
const POWERSOFTAU_FILE: &str = "powersoftau";
const POWERSOFTAU_UNCOMPRESSED_FILE: &str = "powersoftau_uncompressed";
const TAU_POWERS_LENGTH: usize = 1 << 21;
const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

struct PowersOfTau {
    tau_powers_g1: Vec<ArkG1Affine>,
    tau_powers_g2: Vec<ArkG2Affine>,
    alpha_tau_powers_g1: Vec<ArkG1Affine>,
}

use std::path::Path;
fn download_parameters() -> Result<(), minreq::Error> {
    fn check_file_hash(data: &[u8]) -> bool {
        let hash = blake2b_simd::State::new().update(data).finalize().to_hex();
        &hash == POWERSOFTAU_DIGEST
    }

    if Path::new(POWERSOFTAU_FILE).exists() {
        println!("Checking existing {} file...", POWERSOFTAU_FILE);
        let mut f = File::open(POWERSOFTAU_FILE)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        if check_file_hash(&buffer) {
            println!("Checking passed, using existing {} file.", POWERSOFTAU_FILE);
            return Ok(());
        }
    }

    println!("Downloading {}", DOWNLOAD_URL);
    let powersoftau = minreq::get(DOWNLOAD_URL).send()?;
    if !check_file_hash(powersoftau.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed validation (expected: {}, fetched {} bytes)",
                POWERSOFTAU_DIGEST,
                powersoftau.as_bytes().len()
            ),
        )
        .into());
    }

    // Write parameter file.
    let mut f = File::create(POWERSOFTAU_FILE)?;
    f.write_all(powersoftau.as_bytes())?;
    return Ok(());
}

fn powersoftau_uncompress() {
    let response_reader = OpenOptions::new()
        .read(true)
        .open(POWERSOFTAU_FILE)
        .expect(&format!(
            "unable open `{}` in this directory",
            POWERSOFTAU_FILE
        ));

    {
        let metadata = response_reader.metadata().expect(&format!(
            "unable to get filesystem metadata for `{}`",
            POWERSOFTAU_FILE
        ));
        if metadata.len() != (CONTRIBUTION_BYTE_SIZE as u64) {
            panic!(
                "The size of `{}` should be {}, but it's {}, so something isn't right.",
                POWERSOFTAU_FILE,
                CONTRIBUTION_BYTE_SIZE,
                metadata.len()
            );
        }
    }

    let response_reader = BufReader::new(response_reader);
    let mut response_reader = HashReader::new(response_reader);

    {
        let mut response_challenge_hash = [0; 64];
        response_reader
            .read_exact(&mut response_challenge_hash)
            .expect("couldn't read hash of challenge file from response file");
    }

    println!("Started deserializing compressed Powers of Tau...");
    // Load the response's accumulator
    let new_accumulator = Accumulator::deserialize(
        &mut response_reader,
        UseCompression::Yes,
        CheckForCorrectness::No,
    )
    .expect("wasn't able to deserialize the response file's accumulator");

    println!("Done deserializing.");
    let writer = OpenOptions::new()
        .read(false)
        .write(true)
        .create_new(true)
        .open(POWERSOFTAU_UNCOMPRESSED_FILE)
        .expect(&format!("unable to create `{}`", POWERSOFTAU_UNCOMPRESSED_FILE).as_ref());

    let mut writer = BufWriter::new(writer);
    println!("Started serializing unompressed Powers of Tau...");
    new_accumulator
        .serialize(&mut writer, UseCompression::No)
        .expect("wasn't able to deserialize the response file's accumulator");
    println!("Done serializing.");
}

fn load_powersoftau_accumulator() -> io::Result<PowersOfTau> {
    let f = match File::open(POWERSOFTAU_UNCOMPRESSED_FILE) {
        Ok(f) => f,
        Err(e) => {
            panic!(
                "Couldn't load {}. Error: {}",
                POWERSOFTAU_UNCOMPRESSED_FILE, e
            );
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

    Ok(PowersOfTau {
        tau_powers_g1: tau_powers_g1,
        tau_powers_g2: tau_powers_g2,
        alpha_tau_powers_g1: alpha_tau_powers_g1,
    })
}

fn main() {
    download_parameters().unwrap();
    println!("Downloaded Powers of Tau");

    powersoftau_uncompress();

    let params = load_powersoftau_accumulator().unwrap();
    println!("Loaded Powers of Tau");

    println!("Preparing KZG parameters");
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

    println!("Serializing KZG parameters...");
    let buffer = File::create(KZG_SETUP_FILE).unwrap();
    for g in powersoftau.powers_of_g.iter() {
        g.serialize_uncompressed(&buffer).unwrap();
    }
    for g in powersoftau.powers_of_gamma_g.iter() {
        g.serialize_uncompressed(&buffer).unwrap();
    }
    vk.serialize_uncompressed(buffer).unwrap();

    println!(
        "Done serializing. KZG parameters are stored in {}",
        KZG_SETUP_FILE
    );
}
