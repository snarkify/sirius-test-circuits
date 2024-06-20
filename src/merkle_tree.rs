#![allow(dead_code)]

use std::{array, collections::HashMap, fmt, iter, num::NonZeroUsize};

use itertools::Itertools;
use sirius::{
    halo2curves::ff::{FromUniformBytes, PrimeField, PrimeFieldBits},
    poseidon::{PoseidonRO, ROPair},
};
use tracing::*;

use crate::Spec;

use super::{RATE, T};

type Hasher<F> = <PoseidonRO<T, RATE> as ROPair<F>>::OffCircuit;

pub const NUM_BITS: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(255) };

pub fn hash<F>(l: F, r: F) -> F
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    Hasher::digest::<F>(Spec::new(10, 10), &[l, r], NUM_BITS)
}

const DEPTH: u8 = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Level(u8);

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Level {
    pub fn new(level: u8) -> Option<Self> {
        level.le(&31).then_some(Self(level))
    }
    pub const fn zero() -> Self {
        Level(0)
    }
    pub const fn root() -> Self {
        Level(DEPTH - 1)
    }
    pub fn get(&self) -> usize {
        self.0 as usize
    }
    pub fn checked_next(&self) -> Option<Self> {
        Self::new(self.0 + 1)
    }
    pub fn saturating_prev(&self) -> Self {
        Self::new(self.0.saturating_sub(1)).unwrap()
    }
    pub fn iter_all() -> impl Iterator<Item = Self> {
        iter::successors(Some(Level::zero()), Level::checked_next)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Index {
    pub(crate) level: Level,
    pub(crate) index: u32,
}

impl Index {
    pub fn root() -> Self {
        Self {
            level: Level::root(),
            index: 0,
        }
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}][{}]", self.level, self.index)
    }
}

#[derive(Debug, Clone)]
pub enum Sibling<V> {
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

pub struct Tree<F: PrimeField> {
    filled_nodes: HashMap<Index, F>,
    default_values: [F; 32],
}

#[derive(Debug, Clone)]
pub struct NodeUpdate<F> {
    /// Index of node in a level
    pub(crate) index: u32,
    /// Old value, before update
    pub(crate) old: F,
    /// New value, after update
    pub(crate) new: F,
    /// Sibling of this node, to calculate the next level value
    /// None for root
    pub(crate) sibling: Option<F>,
}

impl<F> NodeUpdate<F> {
    pub fn map<T>(self, mut f: impl FnMut(F) -> T) -> NodeUpdate<T> {
        NodeUpdate {
            index: self.index,
            old: f(self.old),
            new: f(self.new),
            sibling: self.sibling.map(f),
        }
    }

    pub fn try_map<T, E>(self, mut f: impl FnMut(F) -> Result<T, E>) -> Result<NodeUpdate<T>, E> {
        Ok(NodeUpdate {
            index: self.index,
            old: f(self.old)?,
            new: f(self.new)?,
            sibling: self.sibling.map(f).transpose()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Proof<F> {
    path: [NodeUpdate<F>; 32],
}

impl<F: PrimeField> Proof<F> {
    pub fn iter(&self) -> impl Iterator<Item = (Level, &NodeUpdate<F>)> {
        Level::iter_all().zip(self.path.iter())
    }

    pub fn into_iter_with_level(self) -> impl Iterator<Item = (Level, NodeUpdate<F>)> {
        Level::iter_all().zip(self.path)
    }
}

impl<F: PrimeField> Proof<F>
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    pub fn verify(&self) -> bool {
        for (level, next_level) in Level::iter_all().tuple_windows() {
            let NodeUpdate {
                index,
                old,
                new,
                sibling,
            } = self.path[level.get()];

            let index = Index { index, level };

            debug!("start work with index: {index}");

            let sibling = index
                .get_sibling()
                .map(|_| sibling.expect("root unreachable"));

            let (old_next_value, new_next_value) = match &sibling {
                Sibling::Left(left) => {
                    debug!("hash left {left:?} with {{ old:{old:?} , new:{new:?} }}");
                    (hash(*left, old), hash(*left, new))
                }
                Sibling::Right(right) => {
                    debug!("hash right {right:?} with {{ old:{old:?} , new:{new:?} }}");
                    (hash(old, *right), hash(new, *right))
                }
            };

            let expected_old = self.path[next_level.get()].old;
            if expected_old != old_next_value {
                error!("`old` not match {expected_old:?} != {old_next_value:?}");
                return false;
            }

            let expected_new = self.path[next_level.get()].new;
            if expected_new != new_next_value {
                error!("`new` not match {expected_new:?} != {new_next_value:?}");
                return false;
            }
        }

        true
    }
}

impl<F: PrimeField> Default for Tree<F>
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    fn default() -> Self {
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
}

impl<F: PrimeField> Tree<F>
where
    F: serde::Serialize + PrimeField + FromUniformBytes<64> + PrimeFieldBits,
{
    pub fn get_root(&self) -> &F {
        self.get_node(Index::root())
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

    pub fn update_leaf(&mut self, index: u32, input: F) -> Proof<F> {
        assert_ne!(index, u32::MAX);

        let mut current = Index {
            level: Level::zero(),
            index,
        };

        let mut paths = array::from_fn(|_| None);
        let new_leaf = hash(input, input);
        let mut sibling = current.get_sibling().map(|s| *self.get_node(s));

        let upd = NodeUpdate {
            index: current.index,
            old: self.update_node(current.clone(), new_leaf),
            new: new_leaf,
            sibling: Some(sibling.clone().unwrap()),
        };

        debug!(
            "hash{current}: sib:{sibling:?} with {current_val:?} is {new_value:?} from {old_value:?}",
            sibling = upd.sibling,
            current_val = new_leaf,
            new_value = upd.new,
            old_value = upd.old
        );

        paths[0] = Some(upd);

        loop {
            debug!("{current}");
            let current_val = *self.get_node(current.clone());

            let new_value = match &sibling {
                Sibling::Left(left) => hash(*left, current_val),
                Sibling::Right(right) => hash(current_val, *right),
            };

            current = current.next_level().unwrap_or_else(|| {
                panic!("root will be found at prev cycle iteration: {:?}", current)
            });

            let old_value = self.update_node(current.clone(), new_value);
            debug!(
                "hash{current}: sib:{sibling:?} with {current_val:?} is {new_value:?} from {old_value:?}"
            );

            sibling = current.get_sibling().map(|s| *self.get_node(s));
            paths[current.level.get()] = Some(NodeUpdate {
                index: current.index,
                old: old_value,
                new: new_value,
                sibling: Some(sibling.clone().unwrap()),
            });

            if current.is_root() {
                break;
            }
        }

        Proof {
            path: paths.map(Option::unwrap),
        }
    }
}

#[cfg(test)]
mod test {
    use sirius::{halo2_proofs::arithmetic::Field, halo2curves::bn256::Fr};

    use tracing_test::traced_test;

    use super::*;

    #[traced_test]
    #[test]
    fn simple_test() {
        let mut tr = Tree::default();
        debug!("{:?}", tr.default_values);
        let mut rng = rand::thread_rng();
        let pr1 = tr.update_leaf(3, Fr::random(&mut rng));
        assert!(pr1.verify());

        let pr2 = tr.update_leaf(3, Fr::random(&mut rng));
        assert!(pr2.verify());

        pr1.path
            .iter()
            .zip(pr2.path.iter())
            .for_each(|(upd1, upd2)| {
                assert_eq!(upd1.index, upd2.index);
                assert_eq!(upd1.new, upd2.old);
                assert_eq!(upd1.sibling, upd2.sibling);
            });

        let pr3 = tr.update_leaf(2u32.pow(31) - 1, Fr::random(&mut rng));
        assert!(pr3.verify());

        pr3.path
            .iter()
            .zip(Level::iter_all())
            .for_each(|(upd, level)| {
                let default = *tr.get_default_value(&level);

                // all nodes, but root, changed
                if level != Level::root() {
                    assert_eq!(upd.old, default, "at {level} & {}", upd.index);
                }

                // sibling not filled only for root
                if let Some(sibling) = upd.sibling {
                    // sibling for 31 level is not default
                    if level != Level::root().saturating_prev() {
                        assert_eq!(sibling, default, "at {level}");
                    }
                }
            });
    }
}
