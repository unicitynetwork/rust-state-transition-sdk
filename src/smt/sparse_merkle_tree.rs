use crate::crypto::sha256_all;
use crate::error::{Result, SdkError};
use crate::types::primitives::DataHash;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::collections::HashMap;

/// Node in the Sparse Merkle Tree
#[derive(Debug, Clone)]
pub struct Node {
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,
    pub hash: Option<DataHash>,
}

impl Node {
    /// Create a new leaf node
    pub fn leaf(hash: DataHash) -> Self {
        Self {
            left: None,
            right: None,
            hash: Some(hash),
        }
    }

    /// Create a new internal node
    pub fn internal(left: Node, right: Node) -> Self {
        Self {
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            hash: None,
        }
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    /// Compute the hash of this node
    pub fn compute_hash(&mut self) -> DataHash {
        if let Some(ref hash) = self.hash {
            return hash.clone();
        }

        let left_hash = self
            .left
            .as_mut()
            .map(|n| n.compute_hash())
            .unwrap_or_else(|| DataHash::sha256(vec![0u8; 32]));

        let right_hash = self
            .right
            .as_mut()
            .map(|n| n.compute_hash())
            .unwrap_or_else(|| DataHash::sha256(vec![0u8; 32]));

        let hash = sha256_all(&[&left_hash.imprint(), &right_hash.imprint()]);
        self.hash = Some(hash.clone());
        hash
    }
}

/// Sparse Merkle Tree implementation
pub struct SparseMerkleTree {
    leaves: HashMap<BigInt, DataHash>,
    root: Option<Node>,
}

impl SparseMerkleTree {
    /// Create a new empty SMT
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            root: None,
        }
    }

    /// Add a leaf to the tree
    pub fn add_leaf(&mut self, index: BigInt, hash: DataHash) -> Result<()> {
        if self.leaves.contains_key(&index) {
            return Err(SdkError::InvalidParameter(format!(
                "Leaf at index {} already exists",
                index
            )));
        }
        self.leaves.insert(index, hash);
        Ok(())
    }

    /// Build the tree from added leaves
    pub fn build(&mut self) -> Result<()> {
        if self.leaves.is_empty() {
            self.root = None;
            return Ok(());
        }

        // Sort leaves by index
        let mut sorted_leaves: Vec<(BigInt, DataHash)> =
            self.leaves.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        sorted_leaves.sort_by(|a, b| a.0.cmp(&b.0));

        // Build tree recursively
        self.root = Some(self.build_recursive(&sorted_leaves, 0)?);
        Ok(())
    }

    /// Build tree recursively
    fn build_recursive(&self, leaves: &[(BigInt, DataHash)], depth: usize) -> Result<Node> {
        if leaves.is_empty() {
            return Err(SdkError::InvalidParameter("Empty leaves".to_string()));
        }

        if leaves.len() == 1 {
            return Ok(Node::leaf(leaves[0].1.clone()));
        }

        // Find split point based on bit at current depth
        let bit_position = self.max_depth() - depth - 1;
        let mut split_idx = 0;

        for i in 0..leaves.len() {
            if self.test_bit(&leaves[i].0, bit_position) {
                split_idx = i;
                break;
            }
        }

        // If no split found, all leaves go to left
        if split_idx == 0 {
            if leaves.iter().all(|l| !self.test_bit(&l.0, bit_position)) {
                // All go left
                let left = self.build_recursive(leaves, depth + 1)?;
                let right = Node::leaf(DataHash::sha256(vec![0u8; 32])); // Empty node
                return Ok(Node::internal(left, right));
            } else {
                // All go right
                let left = Node::leaf(DataHash::sha256(vec![0u8; 32])); // Empty node
                let right = self.build_recursive(leaves, depth + 1)?;
                return Ok(Node::internal(left, right));
            }
        }

        let (left_leaves, right_leaves) = leaves.split_at(split_idx);

        let left = if left_leaves.is_empty() {
            Node::leaf(DataHash::sha256(vec![0u8; 32]))
        } else {
            self.build_recursive(left_leaves, depth + 1)?
        };

        let right = if right_leaves.is_empty() {
            Node::leaf(DataHash::sha256(vec![0u8; 32]))
        } else {
            self.build_recursive(right_leaves, depth + 1)?
        };

        Ok(Node::internal(left, right))
    }

    /// Test if a bit is set at position
    fn test_bit(&self, index: &BigInt, position: usize) -> bool {
        let one = BigInt::one();
        let mask = one << position;
        (index & mask) != BigInt::zero()
    }

    /// Get maximum depth of the tree
    fn max_depth(&self) -> usize {
        256 // Using 256-bit indices
    }

    /// Get the root hash
    pub fn root_hash(&mut self) -> Result<DataHash> {
        match self.root {
            Some(ref mut root) => Ok(root.compute_hash()),
            None => Ok(DataHash::sha256(vec![0u8; 32])),
        }
    }

    /// Generate inclusion proof for a leaf
    pub fn get_proof(&self, index: &BigInt) -> Result<Vec<ProofNode>> {
        let _hash = self.leaves.get(index)
            .ok_or_else(|| SdkError::InvalidParameter("Leaf not found".to_string()))?;

        if self.root.is_none() {
            return Ok(Vec::new());
        }

        let mut proof = Vec::new();
        self.get_proof_recursive(self.root.as_ref().unwrap(), index, 0, &mut proof)?;
        Ok(proof)
    }

    /// Generate proof recursively
    fn get_proof_recursive(
        &self,
        node: &Node,
        index: &BigInt,
        depth: usize,
        proof: &mut Vec<ProofNode>,
    ) -> Result<bool> {
        if node.is_leaf() {
            return Ok(true);
        }

        let bit_position = self.max_depth() - depth - 1;
        let go_right = self.test_bit(index, bit_position);

        if go_right {
            if let Some(ref right) = node.right {
                let found = self.get_proof_recursive(right, index, depth + 1, proof)?;
                if found {
                    let left_hash = node.left.as_ref()
                        .map(|n| n.hash.clone().unwrap_or_else(|| DataHash::sha256(vec![0u8; 32])))
                        .unwrap_or_else(|| DataHash::sha256(vec![0u8; 32]));
                    proof.push(ProofNode::Left(left_hash));
                }
                return Ok(found);
            }
        } else {
            if let Some(ref left) = node.left {
                let found = self.get_proof_recursive(left, index, depth + 1, proof)?;
                if found {
                    let right_hash = node.right.as_ref()
                        .map(|n| n.hash.clone().unwrap_or_else(|| DataHash::sha256(vec![0u8; 32])))
                        .unwrap_or_else(|| DataHash::sha256(vec![0u8; 32]));
                    proof.push(ProofNode::Right(right_hash));
                }
                return Ok(found);
            }
        }

        Ok(false)
    }

    /// Verify an inclusion proof
    pub fn verify_proof(
        leaf_hash: &DataHash,
        _index: &BigInt,
        proof: &[ProofNode],
        root_hash: &DataHash,
    ) -> bool {
        let mut current = leaf_hash.clone();

        for node in proof.iter().rev() {
            current = match node {
                ProofNode::Left(hash) => {
                    sha256_all(&[&hash.imprint(), &current.imprint()])
                }
                ProofNode::Right(hash) => {
                    sha256_all(&[&current.imprint(), &hash.imprint()])
                }
            };
        }

        current == *root_hash
    }

    /// Get number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof node in inclusion proof
#[derive(Debug, Clone)]
pub enum ProofNode {
    Left(DataHash),
    Right(DataHash),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let mut tree = SparseMerkleTree::new();
        tree.build().unwrap();
        let root = tree.root_hash().unwrap();
        assert_eq!(root.data().len(), 32);
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = SparseMerkleTree::new();
        let hash = DataHash::sha256(vec![1, 2, 3]);
        tree.add_leaf(BigInt::from(1), hash.clone()).unwrap();
        tree.build().unwrap();

        let root = tree.root_hash().unwrap();
        assert_ne!(root, hash); // Root should be different due to tree structure
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = SparseMerkleTree::new();

        for i in 0..10 {
            let hash = DataHash::sha256(vec![i as u8]);
            tree.add_leaf(BigInt::from(i), hash).unwrap();
        }

        tree.build().unwrap();
        let root = tree.root_hash().unwrap();
        assert_eq!(root.data().len(), 32);
        assert_eq!(tree.len(), 10);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = SparseMerkleTree::new();

        let leaf_hash = DataHash::sha256(vec![42]);
        let index = BigInt::from(5);

        tree.add_leaf(BigInt::from(1), DataHash::sha256(vec![1])).unwrap();
        tree.add_leaf(index.clone(), leaf_hash.clone()).unwrap();
        tree.add_leaf(BigInt::from(10), DataHash::sha256(vec![10])).unwrap();

        tree.build().unwrap();
        let root = tree.root_hash().unwrap();

        let proof = tree.get_proof(&index).unwrap();
        assert!(!proof.is_empty());

        let valid = SparseMerkleTree::verify_proof(&leaf_hash, &index, &proof, &root);
        assert!(valid);

        // Test with wrong leaf
        let wrong_hash = DataHash::sha256(vec![99]);
        let invalid = SparseMerkleTree::verify_proof(&wrong_hash, &index, &proof, &root);
        assert!(!invalid);
    }

    #[test]
    fn test_duplicate_leaf_error() {
        let mut tree = SparseMerkleTree::new();
        let hash = DataHash::sha256(vec![1]);

        tree.add_leaf(BigInt::from(1), hash.clone()).unwrap();
        let result = tree.add_leaf(BigInt::from(1), hash);

        assert!(result.is_err());
    }
}