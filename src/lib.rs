#![allow(dead_code)]

use std::{array, fmt};

use sirius::{
    halo2_proofs::{
        circuit::{AssignedCell, Chip},
        halo2curves::ff::{FromUniformBytes, PrimeField, PrimeFieldBits},
    },
    main_gate::{self, AssignAdviceFrom, RegionCtx},
    poseidon::{PoseidonRO, ROPair},
};

const T: usize = 3;
const RATE: usize = T - 1;

type HasherChip<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OnCircuit;

pub mod merkle_tree;

type Spec<F> = sirius::poseidon::Spec<F, T, RATE>;

type MainGateConfig = main_gate::MainGateConfig<T>;

pub enum Error {}

#[derive(Debug, Clone)]
pub struct MerkleProof<H: fmt::Debug + Clone + PartialEq, const D: usize> {
    pub source: H,
    pub root: H,
    pub assist: [H; D],
    pub index: u64,
}

#[derive(Default, Clone)]
pub enum Limb<F: PrimeField> {
    #[default]
    None,
    Assigned(AssignedCell<F, F>),
    Unassigned(F),
}

impl<F: PrimeField> Limb<F> {
    fn unwrap_or_default(&self) -> F {
        match self {
            Limb::None => F::default(),
            Limb::Assigned(cell) => cell.value().unwrap().copied().unwrap_or_default(),
            Limb::Unassigned(value) => *value,
        }
    }
}
impl<'a, F: PrimeField> AssignAdviceFrom<'a, F> for Limb<F> {
    fn assign_advice_from<A, AR>(
        ctx: &mut RegionCtx<'a, F>,
        annotation: A,
        dst: sirius::halo2_proofs::plonk::Column<sirius::halo2_proofs::plonk::Advice>,
        src: Self,
    ) -> Result<AssignedCell<F, F>, sirius::halo2_proofs::plonk::Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        match src {
            Limb::None => F::assign_advice_from(ctx, annotation, dst, F::ZERO),
            Limb::Assigned(cell) => AssignedCell::assign_advice_from(ctx, annotation, dst, cell),
            Limb::Unassigned(value) => F::assign_advice_from(ctx, annotation, dst, value),
        }
    }
}

//
//use sirius::halo2_proofs::pairing::bn256::Fr;
//
//use crate::host::ForeignInst::MerkleSet;
//
// Given a merkel tree eg1 with height=3:
// 0
// 1 2
// 3 4 5 6
// 7 8 9 10 11 12 13 14
// A proof of 7 = {source: 7.hash, root: 0.hash, assist: [8.hash,4.hash,2.hash], index: 7}

pub struct MerkleProofState<F: PrimeField, const D: usize> {
    pub source: Limb<F>,
    pub root: Limb<F>, // last is root
    pub assist: [Limb<F>; D],
    pub address: Limb<F>,
    pub zero: Limb<F>,
    pub one: Limb<F>,
}

impl<F: PrimeField, const D: usize> Default for MerkleProofState<F, D> {
    fn default() -> Self {
        MerkleProofState {
            source: Limb::default(),
            root: Limb::default(),
            address: Limb::default(),
            assist: array::from_fn(|_| Limb::default()),
            zero: Limb::default(),
            one: Limb::default(),
        }
    }
}

pub struct MerkleChip<F, const D: usize>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
{
    pub config: MainGateConfig,
    data_hasher_chip: HasherChip<F>,
    merkle_hasher_chip: HasherChip<F>,
    state: MerkleProofState<F, D>,
}

impl<F, const D: usize> Chip<F> for MerkleChip<F, D>
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

impl<F, const D: usize> MerkleChip<F, D>
where
    F: PrimeFieldBits + serde::Serialize + FromUniformBytes<64>,
    F::Repr: PartialEq + fmt::Debug,
{
    pub fn new(config: MainGateConfig, spec: Spec<F>) -> Self {
        MerkleChip {
            merkle_hasher_chip: HasherChip::new(config.clone(), spec.clone()),
            data_hasher_chip: HasherChip::new(config.clone(), spec.clone()),
            config,
            state: MerkleProofState::default(),
        }
    }
}
