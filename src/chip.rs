use itertools::Itertools;
use sirius::{
    halo2_proofs::{
        circuit::AssignedCell,
        halo2curves::ff::{FromUniformBytes, PrimeFieldBits},
    },
    main_gate::{AdviceCyclicAssignor, RegionCtx, WrapValue},
    poseidon::ROCircuitTrait,
};

use super::{merkle_tree, HasherChip, MainGateConfig, Spec};

use crate::merkle_tree::{NodeUpdate, Sibling, NUM_BITS};

pub struct MerkleTreeUpdateChip<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    spec: Spec<F>,
    proof: merkle_tree::Proof<F>,
}

impl<F> MerkleTreeUpdateChip<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    fn new(proof: merkle_tree::Proof<F>) -> Self {
        assert!(proof.verify());
        Self {
            spec: Spec::new(10, 10),
            proof,
        }
    }

    pub fn hasher_chip(&self, config: &MainGateConfig) -> HasherChip<F> {
        HasherChip::new(config.clone(), self.spec.clone())
    }

    /// Return assigned version of `NodeUpdate` with `root` information
    pub fn prove_next_update(
        &self,
        region: &mut RegionCtx<F>,
        config: MainGateConfig,
    ) -> Result<NodeUpdate<AssignedCell<F, F>>, sirius::halo2_proofs::plonk::Error> {
        let mut assigner = config.advice_cycle_assigner::<F>();
        let mut assigned_proof = self
            .proof
            .clone()
            .into_iter_with_level()
            .map(|(level, update)| {
                Result::<_, sirius::halo2_proofs::plonk::Error>::Ok((
                    merkle_tree::Index {
                        index: update.index,
                        level,
                    },
                    update.try_map(|f| assigner.assign_next_advice(region, || "TODO", f))?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        region.next();

        for ((index, update), (_next_index, next_update)) in assigned_proof.iter().tuple_windows() {
            let (old_next, new_next) = match index
                .get_sibling()
                .map(|_| update.sibling.as_ref().expect("root unreachable"))
            {
                Sibling::Left(left) => {
                    let old_next = self
                        .hasher_chip(&config)
                        .update(&[left, &update.old].map(|c| WrapValue::Assigned(c.clone())))
                        .squeeze(region)?;
                    let new_next = self
                        .hasher_chip(&config)
                        .update(&[left, &update.new].map(|c| WrapValue::Assigned(c.clone())))
                        .squeeze(region)?;

                    (old_next, new_next)
                }
                Sibling::Right(right) => {
                    let old_next = self
                        .hasher_chip(&config)
                        .update(&[&update.old, right].map(|c| WrapValue::Assigned(c.clone())))
                        .squeeze(region)?;
                    let new_next = self
                        .hasher_chip(&config)
                        .update(&[&update.new, right].map(|c| WrapValue::Assigned(c.clone())))
                        .squeeze(region)?;

                    (old_next, new_next)
                }
            };

            assert_eq!(old_next.value().unwrap(), next_update.old.value().unwrap());
            region.constrain_equal(old_next.cell(), next_update.old.cell())?;
            region.constrain_equal(new_next.cell(), next_update.new.cell())?;
        }

        Ok(assigned_proof.pop().unwrap().1)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, num::NonZeroUsize, path::Path};

    use rand::Rng;
    use sirius::{
        commitment::CommitmentKey,
        halo2_proofs::{circuit::*, plonk::*},
        halo2curves::{bn256, ff::Field, grumpkin, CurveAffine, CurveExt},
        ivc::{
            step_circuit::trivial, CircuitPublicParamsInput, PublicParams, StepCircuit,
            SynthesisError,
        },
        main_gate::MainGate,
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

    use crate::{RATE, T};

    use super::*;

    struct TestCircuit<F>
    where
        F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
    {
        spec: Spec<F>,
        tree: merkle_tree::Tree<F>,
        last_proof: Option<merkle_tree::Proof<F>>,
    }

    impl<F> Default for TestCircuit<F>
    where
        F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
    {
        fn default() -> Self {
            Self {
                spec: Spec::new(10, 10),
                tree: Default::default(),
                last_proof: None,
            }
        }
    }

    impl<F> TestCircuit<F>
    where
        F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
    {
        fn update_leaf(&mut self, leaf_index: u32, leaf_data: F) {
            self.last_proof = Some(self.tree.update_leaf(leaf_index, leaf_data));
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

                        let NodeUpdate { old, new, .. } =
                            MerkleTreeUpdateChip::new(self.last_proof.clone().unwrap())
                                .prove_next_update(&mut region, config.clone())?;

                        region.constrain_equal(z_i[0].cell(), old.cell())?;

                        Ok([new])
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

    #[test]
    fn circuit() {
        let mut sc1 = TestCircuit::default();
        let mut rng = rand::thread_rng();
        let sc1_default_root = *sc1.tree.get_root();
        sc1.update_leaf(0, C1Scalar::random(&mut rng));

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

        let mut ivc =
            sirius::ivc::IVC::new(&pp, &sc1, [sc1_default_root], &sc2, [C2Scalar::ZERO], true)
                .unwrap();

        sc1.update_leaf(1024, C1Scalar::random(&mut rng));
        ivc.fold_step(&pp, &sc1, &sc2).unwrap();

        sc1.update_leaf(2048, C1Scalar::random(&mut rng));
        ivc.fold_step(&pp, &sc1, &sc2).unwrap();

        sc1.update_leaf(100_000, C1Scalar::random(&mut rng));
        ivc.fold_step(&pp, &sc1, &sc2).unwrap();

        ivc.verify(&pp).unwrap();
    }
}
