use std::{array, io, num::NonZeroUsize, path::Path};

use rand::Rng;
use sirius::{
    commitment::CommitmentKey,
    halo2_proofs::{circuit::*, plonk::*},
    halo2curves::{
        bn256,
        ff::{Field, FromUniformBytes, PrimeFieldBits},
        grumpkin, CurveAffine, CurveExt,
    },
    ivc::{
        step_circuit::trivial, CircuitPublicParamsInput, PublicParams, StepCircuit, SynthesisError,
        IVC,
    },
    main_gate::{MainGate, RegionCtx},
    poseidon::ROPair,
};

use bn256::G1 as C1;
use grumpkin::G1 as C2;
type C1Affine = <C1 as sirius::halo2curves::group::prime::PrimeCurve>::Affine;
type C2Affine = <C2 as sirius::halo2curves::group::prime::PrimeCurve>::Affine;

type C1Scalar = <C1 as sirius::halo2curves::group::Group>::Scalar;
type C2Scalar = <C2 as sirius::halo2curves::group::Group>::Scalar;

type RandomOracle = sirius::poseidon::PoseidonRO<T, RATE>;
type RandomOracleConstant<F> = <RandomOracle as ROPair<F>>::Args;

const LIMB_WIDTH: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(32) };
const LIMBS_COUNT_LIMIT: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(10) };
const COMMITMENT_KEY_SIZE: usize = 21;
const INDEX_LIMIT: u32 = 1 << 31;

use crate::{RATE, T};

use sirius_test_circuits::{chip::MerkleTreeUpdateChip, merkle_tree::NodeUpdate, *};

struct TestCircuit<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    tree: merkle_tree::Tree<F>,
    last_proof: Option<[merkle_tree::Proof<F>; BATCH_SIZE]>,
}

impl<F> Default for TestCircuit<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    fn default() -> Self {
        Self {
            tree: Default::default(),
            last_proof: None,
        }
    }
}

const BATCH_SIZE: usize = 10;

impl<F> TestCircuit<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    fn update_leaves(&mut self, update: &[(u32, F); BATCH_SIZE]) -> (F, F) {
        let proofs = update.map(|(index, data)| self.tree.update_leaf(index, data));

        let old = proofs.first().unwrap().root().old;
        let new = proofs.last().unwrap().root().new;

        self.last_proof = Some(proofs);

        (old, new)
    }
}

impl<F> StepCircuit<1, F> for TestCircuit<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    type Config = MainGateConfig;
    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        MainGate::configure(cs)
    }

    fn synthesize_step(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
        z_i: &[AssignedCell<F, F>; 1],
    ) -> Result<[AssignedCell<F, F>; 1], SynthesisError> {
        layouter
            .assign_region(
                || "",
                |region| {
                    let mut region = RegionCtx::new(region, 0);

                    let mut prev = z_i[0].clone();
                    for proof in self.last_proof.as_ref().unwrap().iter() {
                        let NodeUpdate { old, new, .. } = MerkleTreeUpdateChip::new(proof.clone())
                            .prove_next_update(&mut region, config.clone())?;

                        region.constrain_equal(prev.cell(), old.cell())?;
                        prev = new;
                    }

                    Ok([prev])
                },
            )
            .map_err(SynthesisError::Halo2)
    }
}

fn get_or_create_commitment_key<C: CurveAffine>(
    k: usize,
    label: &'static str,
) -> io::Result<CommitmentKey<C>> {
    const FOLDER: &str = ".cache/examples";

    unsafe { CommitmentKey::load_or_setup_cache(Path::new(FOLDER), label, k) }
}

fn main() {
    let mut rng = rand::thread_rng();

    let mut sc1 = TestCircuit::default();
    let (sc1_default_root, _) = sc1.update_leaves(&array::from_fn(|_| {
        (rng.gen::<u32>() % INDEX_LIMIT, C1Scalar::random(&mut rng))
    }));

    let sc2 = trivial::Circuit::default();

    let primary_commitment_key =
        get_or_create_commitment_key::<C1Affine>(COMMITMENT_KEY_SIZE, "bn256")
            .expect("Failed to get primary key");
    let secondary_commitment_key =
        get_or_create_commitment_key::<C2Affine>(COMMITMENT_KEY_SIZE, "grumpkin")
            .expect("Failed to get secondary key");
    let primary_spec = RandomOracleConstant::<<C1 as CurveExt>::ScalarExt>::new(10, 10);
    let secondary_spec = RandomOracleConstant::<<C2 as CurveExt>::ScalarExt>::new(10, 10);

    let pp = PublicParams::<
        '_,
        1,
        1,
        T,
        C1Affine,
        C2Affine,
        TestCircuit<_>,
        trivial::Circuit<1, C2Scalar>,
        RandomOracle,
        RandomOracle,
    >::new(
        CircuitPublicParamsInput::new(17, &primary_commitment_key, primary_spec, &sc1),
        CircuitPublicParamsInput::new(17, &secondary_commitment_key, secondary_spec, &sc2),
        LIMB_WIDTH,
        LIMBS_COUNT_LIMIT,
    )
    .unwrap();

    let mut ivc = IVC::new(&pp, &sc1, [sc1_default_root], &sc2, [C2Scalar::ZERO], true).unwrap();

    for _step in 0..10 {
        sc1.update_leaves(&array::from_fn(|_| {
            (rng.gen::<u32>() % INDEX_LIMIT, C1Scalar::random(&mut rng))
        }));
        ivc.fold_step(&pp, &sc1, &sc2).unwrap();
    }

    ivc.verify(&pp).unwrap();
}
