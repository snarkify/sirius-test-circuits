#![allow(dead_code)]

use sirius::{
    main_gate::{self},
    poseidon::{PoseidonRO, ROPair},
};

const T: usize = 3;
const RATE: usize = T - 1;

type HasherChip<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OnCircuit;
type Spec<F> = sirius::poseidon::Spec<F, T, RATE>;
type MainGateConfig = main_gate::MainGateConfig<T>;

pub mod merkle_tree;
pub mod chip;
