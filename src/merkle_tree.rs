use std::mem::replace;

use anyhow::{bail, Result};
use solana_program::hash::{hashv, Hash};
use thiserror::Error;

const LEAF_PREFIX: &[u8] = &[0];
const NODE_PREFIX: &[u8] = &[1];

// left prefix and node prefix to make sure hash is unique and prevent preimage attack.
// Refer: https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
#[macro_export]
macro_rules! hash_leaf {
    ($leaf:ident) => {
        hashv(&[LEAF_PREFIX, $leaf.as_ref()])
    };
}
macro_rules! hash_node {
    ($lnode:ident,$rnode:ident) => {
        // The hash function can be easily replace with any other
        hashv(&[NODE_PREFIX, $lnode.as_ref(), $rnode.as_ref()])
    };
}

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Invalid leaf count")]
    InvalidLeafCount,
    #[error("Exceeded leaf count")]
    ExceededLeafCount,
}

pub struct MerkleTree {
    pub(crate) leaf_count: usize,
    pub(crate) cur_leaf_idx: usize,
    pub(crate) nodes: Vec<Hash>,

    pub(crate) height: u32,
    pub(crate) is_dirty: bool, // for lazy root update
    pub(crate) default: Hash,
}

fn tree_height(leaf_count: usize) -> u32 {
    if leaf_count % 2 != 0 {
        return (leaf_count + 1).ilog2();
    }

    leaf_count.ilog2()
}

impl MerkleTree {
    pub fn new(leaf_count: usize, default: Hash) -> Result<Self> {
        if leaf_count == 0 || leaf_count % 2 != 0 {
            bail!(MerkleTreeError::InvalidLeafCount);
        }

        let height = tree_height(leaf_count);
        let capacity = leaf_count << 1;

        Ok(Self {
            height,
            leaf_count,
            is_dirty: false,
            cur_leaf_idx: 0,
            nodes: vec![default; capacity], // pre_init the tree
            default,
        })
    }

    pub fn insert<T>(&mut self, leaf: T) -> Result<usize>
    where
        T: AsRef<[u8]>,
    {
        if self.cur_leaf_idx >= self.leaf_count {
            bail!(MerkleTreeError::ExceededLeafCount);
        }

        let leaf_hash = hash_leaf!(leaf);
        let leaf_idx = self.leaf_count + self.cur_leaf_idx;

        let _ = replace(&mut self.nodes[leaf_idx], leaf_hash);
        self.cur_leaf_idx += 1;
        self.is_dirty = true;

        Ok(self.cur_leaf_idx)
    }

    pub fn get_root(&mut self) -> Option<&Hash> {
        if self.is_dirty {
            self.update_root();
        }
        Some(&self.nodes[1])
    }

    pub fn update_root(&mut self) {
        let mut cur_height = 0;

        let mut from = self.nodes.len() - self.leaf_count;
        let mut to = self.nodes.len();
        while cur_height < self.height {
            for i in (from..to).step_by(2) {
                let left = self.nodes[i];
                let right = self.nodes[i + 1];
                let parent = i / 2;

                let parent_hash = if left == self.default {
                    hash_node!(right, right)
                } else if right == self.default {
                    hash_node!(left, left)
                } else {
                    hash_node!(left, right)
                };
                let _ = replace(&mut self.nodes[parent], parent_hash);
            }

            cur_height += 1;
            let next_level_count = (to + 1 - from) / 2;

            to = from;
            from = to - next_level_count;
        }
    }

    /// Returns the proof for give key
    pub fn prove(&self, key: &Vec<u8>) -> Option<Vec<Hash>> {
        let hash = hash_leaf!(key);
        if hash == self.default {
            return None;
        }

        let from = self.nodes.len() - self.leaf_count;
        let to = self.nodes.len();
        if let Some(mut parent) = self.nodes[from..to].iter().position(|&x| x == hash) {
            parent += from;
            let mut proof = vec![];
            while parent > 0 {
                proof.push(self.nodes[parent]);
                parent /= 2;
            }

            Some(proof)
        } else {
            None
        }
    }

    pub fn verify_proof(&self, proof: &Vec<Hash>) -> bool {
        if proof.len() != (self.height + 1) as usize {
            return false;
        }

        let from = self.nodes.len() - self.leaf_count;
        let to = self.nodes.len();
        if let Some(mut hash_idx) = self.nodes[from..to].iter().position(|&x| x == proof[0]) {
            let mut cur_proof_idx = 0;

            while hash_idx > 0 {
                if self.nodes[hash_idx] != proof[cur_proof_idx] {
                    return false;
                }

                hash_idx /= 2;
                cur_proof_idx += 1;
            }

            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use quickcheck_macros::quickcheck;

    fn sample_tree() -> MerkleTree {
        let mut tree = MerkleTree::new(4, Hash::default()).unwrap();
        tree.insert(b"a").unwrap();
        tree.insert(b"b").unwrap();
        tree.insert(b"c").unwrap();
        tree.insert(b"d").unwrap();
        tree
    }

    #[test]
    fn test_sanity() -> Result<()> {
        let mut tree = sample_tree();
        let root = tree.get_root();
        // dbg!(&root);

        let proof = tree.prove(&b"a".to_vec());
        // dbg!(&proof);

        // verify proof
        let verified = tree.verify_proof(&proof.unwrap());
        assert!(verified);

        Ok(())
    }

    #[test]
    fn test_new_tree() -> Result<()> {
        let tree = MerkleTree::new(0, Hash::default());
        assert!(tree.is_err());
        let err = tree.err().unwrap();
        assert_eq!(err.to_string(), "Invalid leaf count");
        Ok(())
    }

    #[test]
    fn test_insert() -> Result<()> {
        let mut tree2 = MerkleTree::new(2, Hash::default())?;
        tree2.insert(b"a")?;
        tree2.insert(b"b")?;
        let err = tree2.insert(b"c").err().unwrap();
        assert_eq!(err.to_string(), "Exceeded leaf count");
        Ok(())
    }

    #[quickcheck]
    fn fuzz_insert(leaf: Vec<u8>) -> Result<()> {
        let mut tree = MerkleTree::new(4, Hash::default())?;
        tree.insert(leaf)?;
        Ok(())
    }

    // TODO: Fuzz, and benchmark
}
