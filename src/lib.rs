#![allow(dead_code)]

use sirius::{
    main_gate::{self},
    poseidon::{PoseidonRO, ROPair},
};

const T: usize = 4;
const RATE: usize = T - 1;

type HasherChip<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OnCircuit;
type Spec<F> = sirius::poseidon::Spec<F, T, RATE>;
type MainGateConfig = main_gate::MainGateConfig<T>;

pub mod chip;
pub mod merkle_tree;
