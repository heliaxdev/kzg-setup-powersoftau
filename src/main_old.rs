use std::io::{self, BufReader};
use blake2b_simd::State;
use std::io::{Read};
use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use bls12_381::Bls12;
use std::fs::File;
use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_poly::univariate::DensePolynomial as DensePoly;
use ark_std::test_rng;
use ark_poly_commit::kzg10::*;
use ark_poly_commit::*;
use ark_ec::{group::Group, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::UVPolynomial;
use ark_std::{format, marker::PhantomData, ops::Div, vec};

/// Abstraction over a reader which hashes the data being read.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: State,
}
impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader,
            hasher: State::new(),
        }
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> String {
        let hash = self.hasher.finalize();

        let mut s = String::new();
        for c in hash.as_bytes().iter() {
            s += &format!("{:02x}", c);
        }

        s
    }
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}


pub(crate) fn trim_Bls12_381(
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

// pub(crate) fn trim_Bls12_377(
// 	pp: &UniversalParams<Bls12_377>,
// 	mut supported_degree: usize,
// ) -> Result<(Powers<Bls12_377>, VerifierKey<Bls12_377>), Error> {
// 	if supported_degree == 1 {
// 		supported_degree += 1;
// 	}
// 	let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
// 	let powers_of_gamma_g = (0..=supported_degree)
// 		.map(|i| pp.powers_of_gamma_g[&i])
// 		.collect();
// 	let powers = Powers {
// 		powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
// 		powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
// 	};
// 	let vk = VerifierKey {
// 		g: pp.powers_of_g[0],
// 		gamma_g: pp.powers_of_gamma_g[&0],
// 		h: pp.h,
// 		beta_h: pp.beta_h,
// 		prepared_h: pp.prepared_h.clone(),
// 		prepared_beta_h: pp.prepared_beta_h.clone(),
// 	};
// 	Ok((powers, vk))
// }


fn main() {
    let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
    let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
    let mut spend_fs = HashReader::new(spend_fs_buf);

    // Deserialize
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
            .expect("couldn't deserialize Sapling spend parameters file");

    let spend_vk = prepare_verifying_key(&spend_params.vk);

    println!("vk.alpha_g1 = {:?}",  spend_params.vk.alpha_g1);
    println!("vk.beta_g1 = {:?}",   spend_params.vk.beta_g1);
    println!("vk.beta_g2 = {:?}",   spend_params.vk.beta_g2);
    println!("vk.gamma_g2 = {:?}",  spend_params.vk.gamma_g2);
    println!("vk.delta_g1 = {:?}",  spend_params.vk.delta_g1);
    println!("vk.delta_g2 = {:?}",  spend_params.vk.delta_g2);
    println!("vk.ic = {:?}",        spend_params.vk.ic);
    println!("vk.ic.len() = {:?}",        spend_params.vk.ic.len());
    // println!("prepared vk = {:?}",   spend_vk);
    println!("h[0] = {:?}",    spend_params.h[0]);//.len());
    println!("l[0] = {:?}",    spend_params.l[0]);//.len());
    println!("a[0] = {:?}",    spend_params.a[0]);//.len());
    println!("b_g1[0] = {:?}", spend_params.b_g1[0]);//.len());
    println!("b_g2[0] = {:?}", spend_params.b_g2[0]);//.len());
    println!("h.len = {:?}",    spend_params.h.len());
    println!("l.len = {:?}",    spend_params.l.len());
    println!("a.len = {:?}",    spend_params.a.len());
    println!("b_g1.len = {:?}", spend_params.b_g1.len());
    println!("b_g2.len = {:?}", spend_params.b_g2.len());

    //////////////////// KZG //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    println!("========================================================================================");
    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;
    // type UniPoly_377 = DensePoly<<Bls12_377 as PairingEngine>::Fr>;
    type KZG_Bls12_381 = KZG10<Bls12_381, UniPoly_381>;

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

	let degree = 4;
	let pp = KZG_Bls12_381::setup(degree, false, rng).unwrap();
	let (powers, _) = trim_Bls12_381(&pp, degree).unwrap();
    let hiding_bound = None;
	let (comm, _) = KZG10::commit(&powers, &p, hiding_bound, Some(rng)).unwrap();
	let (f_comm, _) = KZG10::commit(&powers, &f_p, hiding_bound, Some(rng)).unwrap();
	let mut f_comm_2 = Commitment::empty();
	f_comm_2 += (f, &comm);

	assert_eq!(f_comm, f_comm_2);
    
    //=======================================================================================================

    // println!("spend_params.a[0] = {:?}", spend_params.a[0]);
    // println!("spend_params.a[1] = {:?}", spend_params.a[1]);
    // println!("spend_params.a[2] = {:?}", spend_params.a[2]);
    // println!("spend_params.a[3] = {:?}", spend_params.a[3]);
    // println!("spend_params.b_g1[0] = {:?}", spend_params.b_g1[0]);
    // println!("spend_params.b_g1[1] = {:?}", spend_params.b_g1[1]);
    // println!("spend_params.b_g1[2] = {:?}", spend_params.b_g1[2]);
    // println!("spend_params.b_g1[3] = {:?}", spend_params.b_g1[3]);

    // type G1Projective = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Projective;
    type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
    type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;

    use ark_serialize::CanonicalDeserialize;

    let mut powers_of_g: Vec<G1Affine> = vec![];
    // let powers_of_gamma_g: Vec<G1Affine>;
    for b_g1 in spend_params.b_g1[0..=degree].iter() {
        let mut tmp = b_g1.to_uncompressed();
        tmp[000..=047].reverse();
        tmp[048..=095].reverse();
        let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
        powers_of_g.push(b_g1_new);
    }

    let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
    for a in spend_params.a[0..=degree].iter() {
        let mut tmp = a.to_uncompressed();
        tmp[000..=047].reverse();
        tmp[048..=095].reverse();
        let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
        powers_of_gamma_g.push(a_new);
    }

    println!("##### powers_of_g\n{:?}\n", powers_of_g);
    println!("##### powers_of_gamma_g\n{:?}\n", powers_of_gamma_g);

//////////////////////////////////////////////////////////////////////
    // let beta = Fr::rand(rng); // TODO change this
    // let mut powers_of_beta = vec![Fr::one()];
    // let g = G1Projective::rand(rng);
    // let gamma_g = G1Projective::rand(rng);
    // let window_size = FixedBaseMSM::get_mul_window_size(degree + 1);
    // let scalar_bits = Fr::size_in_bits();
    // let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);


    // let powers_of_g = FixedBaseMSM::multi_scalar_mul::<G1Projective>(
    //     scalar_bits,
    //     window_size,
    //     &g_table,
    //     &powers_of_beta,
    // );


    // let gamma_g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, gamma_g);
    // let mut powers_of_gamma_g = FixedBaseMSM::multi_scalar_mul::<G1Projective>(
    //     scalar_bits,
    //     window_size,
    //     &gamma_g_table,
    //     &powers_of_beta,
    // );


    // // let powers_of_g = G1Projective::batch_normalization_into_affine(&powers_of_g);
    // powers_of_gamma_g.push(powers_of_gamma_g.last().unwrap().mul(&beta));
    // let powers_of_gamma_g =
    //     G1Projective::batch_normalization_into_affine(&powers_of_gamma_g);
    //         // .into_iter()
    //         // .enumerate()
    //         // .collect();
//////////////////////////////////////////////////////////////////////

    let powers_from_zcash = Powers::<Bls12_381> {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };

    let hiding_bound = None;
	let (comm, _) = KZG10::commit(&powers_from_zcash, &p, hiding_bound, Some(rng)).unwrap();
	let (f_comm, _) = KZG10::commit(&powers_from_zcash, &f_p, hiding_bound, Some(rng)).unwrap();
	let mut f_comm_2 = Commitment::empty();
	f_comm_2 += (f, &comm);

    assert_eq!(f_comm, f_comm_2);

}

fn sapling_setup_Bls12_381(powers: &mut Powers<Bls12_381>, degree: usize) {
    let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
    let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
    let mut spend_fs = HashReader::new(spend_fs_buf);

    // Deserialize
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
            .expect("couldn't deserialize Sapling spend parameters file");

    let spend_vk = prepare_verifying_key(&spend_params.vk);

    type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
    type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;

    use ark_serialize::CanonicalDeserialize;

    let mut powers_of_g: Vec<G1Affine> = vec![];
    for b_g1 in spend_params.b_g1[0..=degree].iter() {
        let mut tmp = b_g1.to_uncompressed();
        tmp[000..=047].reverse();
        tmp[048..=095].reverse();
        let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
        powers_of_g.push(b_g1_new);
    }

    let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
    for a in spend_params.a[0..=degree].iter() {
        let mut tmp = a.to_uncompressed();
        tmp[000..=047].reverse();
        tmp[048..=095].reverse();
        let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
        powers_of_gamma_g.push(a_new);
    }


    let powers = Powers::<Bls12_381> {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
}

#[cfg(test)]
mod tests {
    #![allow(non_camel_case_types)]
    use crate::kzg10::*;
    use crate::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_ec::PairingEngine;
    use ark_poly::univariate::DensePolynomial as DensePoly;
    use ark_std::test_rng;
    type UniPoly_381 = DensePoly<<Bls12_381 as PairingEngine>::Fr>;
    type UniPoly_377 = DensePoly<<Bls12_377 as PairingEngine>::Fr>;
    type KZG_Bls12_381 = KZG10<Bls12_381, UniPoly_381>;

    #[test]
    fn add_commitments_test() {
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

        let degree = 4;
        // let pp = KZG_Bls12_381::setup(degree, false, rng).unwrap();
        // let (powers, _) = trim_Bls12_381(&pp, degree).unwrap();

        ////////////////////////////////////////////////////////////
            let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
            let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
            let mut spend_fs = HashReader::new(spend_fs_buf);
        
            // Deserialize
            let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
                    .expect("couldn't deserialize Sapling spend parameters file");
        
            let spend_vk = prepare_verifying_key(&spend_params.vk);
        
            type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
            type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
        
            use ark_serialize::CanonicalDeserialize;
        
            let mut powers_of_g: Vec<G1Affine> = vec![];
            for b_g1 in spend_params.b_g1[0..=degree].iter() {
                let mut tmp = b_g1.to_uncompressed();
                tmp[000..=047].reverse();
                tmp[048..=095].reverse();
                let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                powers_of_g.push(b_g1_new);
            }
        
            let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
            for a in spend_params.a[0..=degree].iter() {
                let mut tmp = a.to_uncompressed();
                tmp[000..=047].reverse();
                tmp[048..=095].reverse();
                let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                powers_of_gamma_g.push(a_new);
            }
        
        
            let powers = Powers::<Bls12_381> {
                    powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                    powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
                };
        ////////////////////////////////////////////////////////////

        let hiding_bound = None;
        let (comm, _) = KZG10::commit(&powers, &p, hiding_bound, Some(rng)).unwrap();
        let (f_comm, _) = KZG10::commit(&powers, &f_p, hiding_bound, Some(rng)).unwrap();
        let mut f_comm_2 = Commitment::empty();
        f_comm_2 += (f, &comm);

        assert_eq!(f_comm, f_comm_2);
    }

    fn end_to_end_test_template_Bls12_381() -> Result<(), Error>
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }

            // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;
            // let (ck, vk) = trim_Bls12_381(&pp, degree)?;

            ////////////////////////////////////////////////////////////
                let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
                let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
                let mut spend_fs = HashReader::new(spend_fs_buf);
            
                // Deserialize
                let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
                        .expect("couldn't deserialize Sapling spend parameters file");
            
                let spend_vk = prepare_verifying_key(&spend_params.vk);
            
                type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
                type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
                use ark_serialize::CanonicalDeserialize;
            
                let mut powers_of_g: Vec<G1Affine> = vec![];
                for b_g1 in spend_params.b_g1[0..=degree].iter() {
                    let mut tmp = b_g1.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_g.push(b_g1_new);
                }
            
                let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
                for a in spend_params.a[0..=degree].iter() {
                    let mut tmp = a.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_gamma_g.push(a_new);
                }
            
            
                let ck = Powers::<Bls12_381> {
                        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
                    };

            // println!("vk.alpha_g1 = {:?}",  spend_params.vk.alpha_g1);
            // println!("vk.beta_g1 = {:?}",   spend_params.vk.beta_g1);
            // println!("vk.beta_g2 = {:?}",   spend_params.vk.beta_g2);
            // println!("vk.gamma_g2 = {:?}",  spend_params.vk.gamma_g2);
            // println!("vk.delta_g1 = {:?}",  spend_params.vk.delta_g1);
            // println!("vk.delta_g2 = {:?}",  spend_params.vk.delta_g2);
            // println!("vk.ic = {:?}",        spend_params.vk.ic);
            // println!("vk.ic.len() = {:?}",        spend_params.vk.ic.len());
            // // println!("prepared vk = {:?}",   spend_vk);

                // pub struct VerifierKey<E: PairingEngine> {
                //     /// The generator of G1.
                //     pub g: E::G1Affine,
                //     /// The generator of G1 that is used for making a commitment hiding.
                //     pub gamma_g: E::G1Affine,
                //     /// The generator of G2.
                //     pub h: E::G2Affine,
                //     /// \beta times the above generator of G2.
                //     pub beta_h: E::G2Affine,
                //     /// The generator of G2, prepared for use in pairings.
                //     #[derivative(Debug = "ignore")]
                //     pub prepared_h: E::G2Prepared,
                //     /// \beta times the above generator of G2, prepared for use in pairings.
                //     #[derivative(Debug = "ignore")]
                //     pub prepared_beta_h: E::G2Prepared,
                // }

            // let vk = VerifierKey {
            //     g: ck.powers_of_g[0],
            //     gamma_g: ck.powers_of_gamma_g[0],
            //     h: pp.h,
            //     beta_h: pp.beta_h,
            //     prepared_h: pp.prepared_h.clone(),
            //     prepared_beta_h: pp.prepared_beta_h.clone(),
            // };

            ////////////////////////////////////////////////////////////

            let p = UniPoly_381::rand(degree, rng);
            let hiding_bound = Some(1);
            let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&ck, &p, hiding_bound, Some(rng))?;
            let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof = KZG10::<Bls12_381, UniPoly_381>::open(&ck, &p, point, &rand)?;
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

    // fn end_to_end_test_template_Bls12_377() -> Result<(), Error>
    // {
    //     let rng = &mut test_rng();
    //     for _ in 0..100 {
    //         let mut degree = 0;
    //         while degree <= 1 {
    //             degree = usize::rand(rng) % 20;
    //         }
    //         // let pp = KZG10::<Bls12_377, UniPoly_377>::setup(degree, false, rng)?;


    //         ////////////////////////////////////////////////////////////
    //             let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
    //             let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
    //             let mut spend_fs = HashReader::new(spend_fs_buf);
            
    //             // Deserialize
    //             let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
    //                     .expect("couldn't deserialize Sapling spend parameters file");
            
    //             let spend_vk = prepare_verifying_key(&spend_params.vk);
            
    //             type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
    //             type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
    //             use ark_serialize::CanonicalDeserialize;
            
    //             let mut powers_of_g: Vec<G1Affine> = vec![];
    //             for b_g1 in spend_params.b_g1[0..=degree].iter() {
    //                 let mut tmp = b_g1.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_g.push(b_g1_new);
    //             }
            
    //             let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
    //             for a in spend_params.a[0..=degree].iter() {
    //                 let mut tmp = a.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_gamma_g.push(a_new);
    //             }
            
            
    //             let ck = Powers::<Bls12_377> {
    //                     powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
    //                     powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    //                 };
    //         ////////////////////////////////////////////////////////////


    //         // let (ck, vk) = trim_Bls12_377(&pp, degree)?;
    //         let p = UniPoly_377::rand(degree, rng);
    //         let hiding_bound = Some(1);
    //         let (comm, rand) = KZG10::<Bls12_377, UniPoly_377>::commit(&ck, &p, hiding_bound, Some(rng))?;
    //         let point = <ark_ec::bls12::Bls12<ark_bls12_377::Parameters> as PairingEngine>::Fr::rand(rng);
    //         let value = p.evaluate(&point);
    //         let proof = KZG10::<Bls12_377, UniPoly_377>::open(&ck, &p, point, &rand)?;
    //         assert!(
    //             KZG10::<Bls12_377, UniPoly_377>::check(&vk, &comm, point, value, &proof)?,
    //             "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
    //             degree,
    //             p.degree(),
    //             hiding_bound,
    //         );
    //     }
    //     Ok(())
    // }

    // fn linear_polynomial_test_template_Bls12_377() -> Result<(), Error>
    // {
    //     let rng = &mut test_rng();
    //     for _ in 0..100 {
    //         let degree = 50;
    //         // let pp = KZG10::<Bls12_377, UniPoly_377>::setup(degree, false, rng)?;

    //         ////////////////////////////////////////////////////////////
    //             let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
    //             let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
    //             let mut spend_fs = HashReader::new(spend_fs_buf);
            
    //             // Deserialize
    //             let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
    //                     .expect("couldn't deserialize Sapling spend parameters file");
            
    //             let spend_vk = prepare_verifying_key(&spend_params.vk);
            
    //             type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
    //             type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
    //             use ark_serialize::CanonicalDeserialize;
            
    //             let mut powers_of_g: Vec<G1Affine> = vec![];
    //             for b_g1 in spend_params.b_g1[0..=degree].iter() {
    //                 let mut tmp = b_g1.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_g.push(b_g1_new);
    //             }
            
    //             let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
    //             for a in spend_params.a[0..=degree].iter() {
    //                 let mut tmp = a.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_gamma_g.push(a_new);
    //             }
            
            
    //             let powers = Powers::<Bls12_381> {
    //                     powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
    //                     powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    //                 };
    //         ////////////////////////////////////////////////////////////
                
    //         let (ck, vk) = trim_Bls12_377(&pp, 2)?;
    //         let p = UniPoly_377::rand(1, rng);
    //         let hiding_bound = Some(1);
    //         let (comm, rand) = KZG10::<Bls12_377, UniPoly_377>::commit(&ck, &p, hiding_bound, Some(rng))?;
    //         let point = <ark_ec::bls12::Bls12<ark_bls12_377::Parameters> as PairingEngine>::Fr::rand(rng);
    //         let value = p.evaluate(&point);
    //         let proof = KZG10::<Bls12_377, UniPoly_377>::open(&ck, &p, point, &rand)?;
    //         assert!(
    //             KZG10::<Bls12_377, UniPoly_377>::check(&vk, &comm, point, value, &proof)?,
    //             "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
    //             degree,
    //             p.degree(),
    //             hiding_bound,
    //         );
    //     }
    //     Ok(())
    // }

    fn linear_polynomial_test_template_Bls12_381() -> Result<(), Error>
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let degree = 50;
            // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;

            ////////////////////////////////////////////////////////////
                let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
                let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
                let mut spend_fs = HashReader::new(spend_fs_buf);
            
                // Deserialize
                let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
                        .expect("couldn't deserialize Sapling spend parameters file");
            
                let spend_vk = prepare_verifying_key(&spend_params.vk);
            
                type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
                type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
                use ark_serialize::CanonicalDeserialize;
            
                let mut powers_of_g: Vec<G1Affine> = vec![];
                for b_g1 in spend_params.b_g1[0..=degree].iter() {
                    let mut tmp = b_g1.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_g.push(b_g1_new);
                }
            
                let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
                for a in spend_params.a[0..=degree].iter() {
                    let mut tmp = a.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_gamma_g.push(a_new);
                }
            
            
                let ck = Powers::<Bls12_381> {
                        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
                    };
            ////////////////////////////////////////////////////////////
            
            // let (ck, vk) = trim_Bls12_381(&pp, 2)?;
            let p = UniPoly_381::rand(1, rng);
            let hiding_bound = Some(1);
            let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&ck, &p, hiding_bound, Some(rng))?;
            let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
            let value = p.evaluate(&point);
            let proof = KZG10::<Bls12_381, UniPoly_381>::open(&ck, &p, point, &rand)?;
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

    fn batch_check_test_template_Bls12_381() -> Result<(), Error>
    {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            // let pp = KZG10::<Bls12_381, UniPoly_381>::setup(degree, false, rng)?;

            ////////////////////////////////////////////////////////////
                let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
                let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
                let mut spend_fs = HashReader::new(spend_fs_buf);
            
                // Deserialize
                let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
                        .expect("couldn't deserialize Sapling spend parameters file");
            
                let spend_vk = prepare_verifying_key(&spend_params.vk);
            
                type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
                type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
                use ark_serialize::CanonicalDeserialize;
            
                let mut powers_of_g: Vec<G1Affine> = vec![];
                for b_g1 in spend_params.b_g1[0..=degree].iter() {
                    let mut tmp = b_g1.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_g.push(b_g1_new);
                }
            
                let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
                for a in spend_params.a[0..=degree].iter() {
                    let mut tmp = a.to_uncompressed();
                    tmp[000..=047].reverse();
                    tmp[048..=095].reverse();
                    let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                    powers_of_gamma_g.push(a_new);
                }
            
            
                let ck = Powers::<Bls12_381> {
                        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
                    };
            ////////////////////////////////////////////////////////////

            // let (ck, vk) = trim_Bls12_381(&pp, degree)?;
            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();
            for _ in 0..10 {
                let p = UniPoly_381::rand(degree, rng);
                let hiding_bound = Some(1);
                let (comm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&ck, &p, hiding_bound, Some(rng))?;
                let point = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr::rand(rng);
                let value = p.evaluate(&point);
                let proof = KZG10::<Bls12_381, UniPoly_381>::open(&ck, &p, point, &rand)?;

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

    // fn batch_check_test_template_Bls12_377() -> Result<(), Error>
    // {
    //     let rng = &mut test_rng();
    //     for _ in 0..10 {
    //         let mut degree = 0;
    //         while degree <= 1 {
    //             degree = usize::rand(rng) % 20;
    //         }
    //         // let pp = KZG10::<Bls12_377, UniPoly_377>::setup(degree, false, rng)?;

    //         ////////////////////////////////////////////////////////////
    //             let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
    //             let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
    //             let mut spend_fs = HashReader::new(spend_fs_buf);
            
    //             // Deserialize
    //             let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
    //                     .expect("couldn't deserialize Sapling spend parameters file");
            
    //             let spend_vk = prepare_verifying_key(&spend_params.vk);
            
    //             type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
    //             type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
            
    //             use ark_serialize::CanonicalDeserialize;
            
    //             let mut powers_of_g: Vec<G1Affine> = vec![];
    //             for b_g1 in spend_params.b_g1[0..=degree].iter() {
    //                 let mut tmp = b_g1.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_g.push(b_g1_new);
    //             }
            
    //             let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
    //             for a in spend_params.a[0..=degree].iter() {
    //                 let mut tmp = a.to_uncompressed();
    //                 tmp[000..=047].reverse();
    //                 tmp[048..=095].reverse();
    //                 let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
    //                 powers_of_gamma_g.push(a_new);
    //             }
            
            
    //             let powers = Powers::<Bls12_381> {
    //                     powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
    //                     powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    //                 };
    //         ////////////////////////////////////////////////////////////

    //         let (ck, vk) = trim_Bls12_377(&pp, degree)?;
    //         let mut comms = Vec::new();
    //         let mut values = Vec::new();
    //         let mut points = Vec::new();
    //         let mut proofs = Vec::new();
    //         for _ in 0..10 {
    //             let p = UniPoly_377::rand(degree, rng);
    //             let hiding_bound = Some(1);
    //             let (comm, rand) = KZG10::<Bls12_377, UniPoly_377>::commit(&ck, &p, hiding_bound, Some(rng))?;
    //             let point = <ark_ec::bls12::Bls12<ark_bls12_377::Parameters> as PairingEngine>::Fr::rand(rng);
    //             let value = p.evaluate(&point);
    //             let proof = KZG10::<Bls12_377, UniPoly_377>::open(&ck, &p, point, &rand)?;

    //             assert!(KZG10::<Bls12_377, UniPoly_377>::check(&vk, &comm, point, value, &proof)?);
    //             comms.push(comm);
    //             values.push(value);
    //             points.push(point);
    //             proofs.push(proof);
    //         }
    //         assert!(KZG10::<Bls12_377, UniPoly_377>::batch_check(
    //             &vk, &comms, &points, &values, &proofs, rng
    //         )?);
    //     }
    //     Ok(())
    // }

    #[test]
    fn end_to_end_test() {
        // end_to_end_test_template_Bls12_377().expect("test failed for bls12-377");
        end_to_end_test_template_Bls12_381().expect("test failed for bls12-381");
    }

    #[test]
    fn linear_polynomial_test() {
        // linear_polynomial_test_template_Bls12_377().expect("test failed for bls12-377");
        linear_polynomial_test_template_Bls12_381().expect("test failed for bls12-381");
    }
    #[test]
    fn batch_check_test() {
        // batch_check_test_template_Bls12_377().expect("test failed for bls12-377");
        batch_check_test_template_Bls12_381().expect("test failed for bls12-381");
    }

    #[test]
    fn test_degree_is_too_large() {
        let rng = &mut test_rng();

        let max_degree = 123;
        // let pp = KZG_Bls12_381::setup(max_degree, false, rng).unwrap();

        ////////////////////////////////////////////////////////////
            let spend_fs_1 = File::open("sapling-spend.params").expect("couldn't load Sapling spend parameters file");
            let spend_fs_buf = BufReader::with_capacity(1024 * 1024, spend_fs_1);
            let mut spend_fs = HashReader::new(spend_fs_buf);
        
            // Deserialize
            let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
                    .expect("couldn't deserialize Sapling spend parameters file");
        
            let spend_vk = prepare_verifying_key(&spend_params.vk);
        
            type Fr = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::Fr;
            type G1Affine = <ark_ec::bls12::Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
        
            use ark_serialize::CanonicalDeserialize;
        
            let mut powers_of_g: Vec<G1Affine> = vec![];
            for b_g1 in spend_params.b_g1[0..=max_degree].iter() {
                let mut tmp = b_g1.to_uncompressed();
                tmp[000..=047].reverse();
                tmp[048..=095].reverse();
                let b_g1_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                powers_of_g.push(b_g1_new);
            }
        
            let mut powers_of_gamma_g: Vec<G1Affine> = vec![];
            for a in spend_params.a[0..=max_degree].iter() {
                let mut tmp = a.to_uncompressed();
                tmp[000..=047].reverse();
                tmp[048..=095].reverse();
                let a_new = G1Affine::deserialize_uncompressed(&tmp[..]).unwrap();
                powers_of_gamma_g.push(a_new);
            }
        
        
            let powers = Powers::<Bls12_381> {
                    powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
                    powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
                };
        ////////////////////////////////////////////////////////////
        // let (powers, _) = trim_Bls12_381(&pp, max_degree).unwrap();

        let p = DensePoly::<Fr>::rand(max_degree + 1, rng);
        assert!(p.degree() > max_degree);
        assert!(KZG_Bls12_381::check_degree_is_too_large(p.degree(), powers.size()).is_err());
    }
}
