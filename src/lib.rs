#![allow(dead_code)]
pub use sirius::{
    main_gate::{self},
    poseidon::{PoseidonRO, ROPair},
};

pub const T: usize = 4;
pub const RATE: usize = T - 1;

pub type HasherChip<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OnCircuit;
pub type Spec<F> = sirius::poseidon::Spec<F, T, RATE>;
pub type MainGateConfig = main_gate::MainGateConfig<T>;

pub mod chip;
pub mod merkle_tree;
