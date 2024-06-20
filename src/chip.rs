use std::{cell::RefCell, collections::VecDeque};

use itertools::Itertools;
use sirius::{
    halo2_proofs::{
        circuit::AssignedCell,
        halo2curves::ff::{FromUniformBytes, PrimeFieldBits},
    },
    main_gate::{AdviceCyclicAssignor, RegionCtx, WrapValue},
};

use super::{merkle_tree, HasherChip, MainGateConfig, Spec};

use crate::merkle_tree::{NodeUpdate, Sibling};
pub struct MerkleTreeUpdateChip<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    spec: Spec<F>,
    tree: merkle_tree::Tree<F>,
    proofs: RefCell<VecDeque<merkle_tree::Proof<F>>>,
}

impl<F> MerkleTreeUpdateChip<F>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    pub fn update_leaf(&mut self, index: u32, new_leaf: F) {
        let proof = self.tree.update_leaf(index, new_leaf);
        self.proofs.borrow_mut().push_back(proof);
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
        let proof = self
            .proofs
            .borrow_mut()
            .pop_front()
            .expect("proofs not presented");

        assert!(proof.verify());

        let mut assigner = config.advice_cycle_assigner::<F>();
        let mut assigned_proof = proof
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

            region.constrain_equal(old_next.cell(), next_update.old.cell())?;
            region.constrain_equal(new_next.cell(), next_update.new.cell())?;
        }

        Ok(assigned_proof.pop().unwrap().1)
    }
}

#[cfg(test)]
mod tests {
    use sirius::halo2_proofs::{circuit::*, plonk::*};
    use sirius::ivc::StepCircuit;
    use sirius::ivc::SynthesisError;
    use sirius::main_gate::MainGate;

    use super::*;

    struct TestCircuit<F>
    where
        F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
    {
        pub chip: MerkleTreeUpdateChip<F>,
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
                            self.chip.prove_next_update(&mut region, config.clone())?;

                        region.constrain_equal(z_i[0].cell(), old.cell())?;

                        Ok([new])
                    },
                )
                .map_err(SynthesisError::Halo2)
        }
    }

    #[test]
    fn circuit() {}
}
