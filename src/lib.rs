#![allow(dead_code)]

use std::collections::VecDeque;

use itertools::Itertools;
use sirius::{
    halo2_proofs::{
        circuit::{AssignedCell, Chip, Value},
        halo2curves::ff::{FromUniformBytes, PrimeFieldBits},
        plonk,
    },
    main_gate::{self, AdviceCyclicAssignor, MainGate, RegionCtx, WrapValue},
    poseidon::{PoseidonRO, ROPair},
};

use crate::merkle_tree::{NodeUpdate, Sibling};

const T: usize = 3;
const RATE: usize = T - 1;

type HasherChip<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OnCircuit;

pub mod merkle_tree;

type Spec<F> = sirius::poseidon::Spec<F, T, RATE>;

type MainGateConfig = main_gate::MainGateConfig<T>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Error(#[from] plonk::Error),
}

pub struct MerkleTreeUpdateChip<F, const D: usize>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    pub config: MainGateConfig,
    hasher_chip: HasherChip<F>,
    tree: merkle_tree::Tree<F>,
    proofs: VecDeque<merkle_tree::Proof<F>>,
}

impl<F, const D: usize> MerkleTreeUpdateChip<F, D>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    pub fn update_leaf(&mut self, index: u32, new_leaf: F) {
        let proof = self.tree.update_leaf(index, new_leaf);
        self.proofs.push_back(proof);
    }

    pub fn prove_next_update(
        &mut self,
        region: &mut RegionCtx<F>,
    ) -> Result<NodeUpdate<AssignedCell<F, F>>, sirius::halo2_proofs::plonk::Error> {
        let proof = self.proofs.pop_front().unwrap();

        let mut assigner = self.config.advice_cycle_assigner::<F>();
        let mut assigned_proof = proof
            .into_iter()
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
                    let old_calculated_next = self
                        .hasher_chip
                        .update(&[left.clone(), update.old.clone()].map(WrapValue::Assigned))
                        .squeeze(region)?;
                    let new_calculated_next = self
                        .hasher_chip
                        .update(&[left.clone(), update.new.clone()].map(WrapValue::Assigned))
                        .squeeze(region)?;

                    (old_calculated_next, new_calculated_next)
                }
                Sibling::Right(right) => {
                    let old_calculated_next = self
                        .hasher_chip
                        .update(&[update.old.clone(), right.clone()].map(WrapValue::Assigned))
                        .squeeze(region)?;
                    let new_calculated_next = self
                        .hasher_chip
                        .update(&[update.new.clone(), right.clone()].map(WrapValue::Assigned))
                        .squeeze(region)?;

                    (old_calculated_next, new_calculated_next)
                }
            };

            region.constrain_equal(old_next.cell(), next_update.old.cell())?;
            region.constrain_equal(new_next.cell(), next_update.new.cell())?;
        }

        Ok(assigned_proof.pop().unwrap().1)
    }
}

impl<F, const D: usize> Chip<F> for MerkleTreeUpdateChip<F, D>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    type Config = MainGateConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
