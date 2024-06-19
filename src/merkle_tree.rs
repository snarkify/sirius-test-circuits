#![allow(dead_code)]

use std::{array, collections::HashMap, num::NonZeroUsize};

use sirius::{
    halo2curves::ff::{FromUniformBytes, PrimeField, PrimeFieldBits},
    poseidon::{PoseidonRO, ROPair},
};

use crate::Spec;

use super::{RATE, T};

type Hasher<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OffCircuit;

fn hash<F>(l: F, r: F) -> F
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    Hasher::digest::<F>(Spec::new(10, 10), &[l, r], NonZeroUsize::new(32).unwrap())
}

const DEPTH: u8 = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Level(u8);

impl Level {
    pub fn new(level: u8) -> Option<Self> {
        level.le(&31).then_some(Self(level))
    }
    pub fn zero() -> Self {
        Level(0)
    }
    pub fn root() -> Self {
        Level(31)
    }
    pub fn get(&self) -> usize {
        self.0 as usize
    }
    pub fn checked_next(&self) -> Option<Self> {
        Self::new(self.0 + 1)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Index {
    level: Level,
    index: u32,
}

impl Index {
    pub fn is_root(&self) -> bool {
        matches!(
            &self,
            Index {
                index: 0,
                level: Level(DEPTH)
            },
        )
    }

    pub fn next_level(&self) -> Option<Self> {
        Some(Self {
            level: self.level.checked_next()?,
            index: self.index.div_ceil(2),
        })
    }
    pub fn get_sibling(&self) -> Self {
        Self {
            level: self.level.clone(),
            index: if self.index % 2 == 0 {
                self.index + 1
            } else {
                self.index - 1
            },
        }
    }
}

struct MerkleTree<F: PrimeField> {
    filled_nodes: HashMap<Index, F>,
    default_values: [F; 32],
}

#[derive(Debug)]
struct Update<F: PrimeField> {
    index: u32,
    old: F,
    new: F,
}

#[derive(Debug)]
pub struct UpdateProof<F: PrimeField> {
    path: [Update<F>; 32],
}

impl<F: PrimeField> MerkleTree<F>
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    pub fn new() -> Self {
        let mut default_values = [F::ZERO; 32];

        for lvl in 1..(DEPTH as usize) {
            let previous_level_value = default_values[lvl - 1];
            default_values[lvl] = hash(previous_level_value, previous_level_value);
        }

        Self {
            default_values,
            filled_nodes: HashMap::new(),
        }
    }

    fn get_default_value(&self, level: &Level) -> &F {
        self.default_values.get(level.get()).unwrap()
    }

    fn get_node(&self, index: Index) -> &F {
        self.filled_nodes
            .get(&index)
            .unwrap_or_else(|| self.get_default_value(&index.level))
    }

    fn update_node(&mut self, index: Index, new_value: F) -> F {
        self.filled_nodes
            .insert(index.clone(), new_value)
            .unwrap_or_else(|| *self.get_default_value(&index.level))
    }

    pub fn update_leaf(&mut self, index: u32, input: F) -> UpdateProof<F> {
        let mut current = Index {
            level: Level::zero(),
            index,
        };
        let mut new_value = hash(input, input);

        let mut path = array::from_fn(|_| None);

        loop {
            let old_value = self.update_node(current.clone(), new_value);

            new_value = hash(
                *self.get_node(current.clone()),
                *self.get_node(current.get_sibling()),
            );

            path[current.level.get()] = Some(Update {
                index: current.index,
                old: old_value,
                new: new_value,
            });

            match current.next_level() {
                Some(next) => {
                    current = next;
                }
                None => {
                    break;
                }
            }
        }

        UpdateProof {
            path: path.map(Option::unwrap),
        }
    }
}
#[cfg(test)]
mod test {
    use sirius::{halo2_proofs::arithmetic::Field, halo2curves::bn256::Fr};

    use super::*;

    #[test]
    fn simple_test() {
        let mut tr = MerkleTree::new();
        let mut rng = rand::thread_rng();
        let pr1 = tr.update_leaf(0, Fr::random(&mut rng));
        let pr2 = tr.update_leaf(0, Fr::random(&mut rng));
        let pr3 = tr.update_leaf(2, Fr::random(&mut rng));

        panic!("{pr1:?} {pr2:?} {pr3:?}");
    }
}
