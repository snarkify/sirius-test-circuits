#![allow(dead_code)]

use std::{array, collections::HashMap, iter, num::NonZeroUsize};

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
    Hasher::digest::<F>(Spec::new(10, 10), &[l, r], NonZeroUsize::new(128).unwrap())
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
        Level(DEPTH - 1)
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

#[derive(Debug)]
enum Sibling<V> {
    Left(V),
    Right(V),
}

impl<V> Sibling<V> {
    pub fn map<T>(self, f: impl FnOnce(V) -> T) -> Sibling<T> {
        match self {
            Sibling::Left(l) => Sibling::Left(f(l)),
            Sibling::Right(r) => Sibling::Right(f(r)),
        }
    }
    pub fn unwrap(self) -> V {
        match self {
            Sibling::Left(l) => l,
            Sibling::Right(r) => r,
        }
    }
}

impl Index {
    pub fn is_root(&self) -> bool {
        matches!(
            &self,
            Index {
                index: 0,
                level: Level(31)
            },
        )
    }

    pub fn next_level(&self) -> Option<Self> {
        Some(Self {
            level: self.level.checked_next()?,
            index: self.index / 2,
        })
    }
    pub fn get_sibling(&self) -> Sibling<Self> {
        let level = self.level.clone();

        if self.index % 2 == 0 {
            Sibling::Right(Self {
                level,
                index: self.index + 1,
            })
        } else {
            Sibling::Left(Self {
                level,
                index: self.index - 1,
            })
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
    sibling: Option<F>,
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
        let mut default_values = [hash(F::ZERO, F::ZERO); 32];

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

        let mut paths = array::from_fn(|_| None);
        let new_leaf = hash(input, input);
        paths[0] = Some(Update {
            index: current.index,
            old: self.update_node(current.clone(), new_leaf),
            new: new_leaf,
            sibling: None,
        });

        loop {
            let current_val = *self.get_node(current.clone());
            let sibling = current.get_sibling().map(|s| *self.get_node(s));

            let new_value = match &sibling {
                Sibling::Left(left) => hash(*left, current_val),
                Sibling::Right(right) => hash(current_val, *right),
            };

            current = current
                .next_level()
                .expect("root will be found at prev cycle iteration");

            let old_value = self.update_node(current.clone(), new_value);
            paths[current.level.get()] = Some(Update {
                index: current.index,
                old: old_value,
                new: new_value,
                sibling: Some(sibling.unwrap()),
            });

            if current.is_root() {
                break;
            }
        }

        UpdateProof {
            path: paths.map(Option::unwrap),
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
        let pr1 = tr.update_leaf(3, Fr::random(&mut rng));
        let pr2 = tr.update_leaf(3, Fr::random(&mut rng));

        dbg!(pr1);
        dbg!(pr2);
        panic!()
    }
}
