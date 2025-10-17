use crate::crypto::sha256_all;
use crate::prelude::*;
use crate::types::primitives::DataHash;
use crate::types::transaction::{PathDirection, PathElement};
use num_bigint::BigInt;
use crate::prelude::*;


/// Merkle tree path for inclusion proofs
#[derive(Debug, Clone)]
pub struct MerkleTreePath {
    pub elements: Vec<PathElement>,
    pub leaf_index: BigInt,
}

impl MerkleTreePath {
    /// Create a new Merkle tree path
    pub fn new(elements: Vec<PathElement>, leaf_index: BigInt) -> Self {
        Self {
            elements,
            leaf_index,
        }
    }

    /// Compute the root hash from a leaf hash
    pub fn compute_root(&self, leaf_hash: &DataHash) -> DataHash {
        let mut current = leaf_hash.clone();

        for element in &self.elements {
            current = match element.direction {
                PathDirection::Left => sha256_all(&[&element.hash.imprint(), &current.imprint()]),
                PathDirection::Right => sha256_all(&[&current.imprint(), &element.hash.imprint()]),
            };
        }

        current
    }

    /// Verify the path against a root hash
    pub fn verify(&self, leaf_hash: &DataHash, root_hash: &DataHash) -> bool {
        self.compute_root(leaf_hash) == *root_hash
    }

    /// Get the depth of the path
    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// Check if path is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Convert to inclusion proof format
    pub fn to_inclusion_proof_path(&self) -> Vec<PathElement> {
        self.elements.clone()
    }
}

/// Common path utilities for finding shared paths
pub struct CommonPath;

impl CommonPath {
    /// Find the longest common prefix between two paths
    pub fn find_common_prefix(path1: &[PathElement], path2: &[PathElement]) -> Vec<PathElement> {
        let mut common = Vec::new();
        let min_len = path1.len().min(path2.len());

        for i in 0..min_len {
            if path1[i].direction == path2[i].direction && path1[i].hash == path2[i].hash {
                common.push(path1[i].clone());
            } else {
                break;
            }
        }

        common
    }

    /// Compute the divergence point between two indices
    pub fn divergence_depth(index1: &BigInt, index2: &BigInt) -> usize {
        let xor = index1 ^ index2;
        if xor == BigInt::from(0) {
            return 256; // Maximum depth if indices are equal
        }

        // Find the highest bit position where they differ
        let bits = xor.bits();
        256 - bits as usize
    }

    /// Check if two paths are for sibling nodes
    pub fn are_siblings(path1: &MerkleTreePath, path2: &MerkleTreePath) -> bool {
        if path1.depth() != path2.depth() {
            return false;
        }

        // Check if indices differ only in the last bit
        let xor = &path1.leaf_index ^ &path2.leaf_index;
        xor == BigInt::from(1) || {
            let shift = path1.depth() - 1;
            xor == (BigInt::from(1) << shift)
        }
    }
}

/// Path builder for constructing Merkle paths
pub struct PathBuilder {
    elements: Vec<PathElement>,
}

impl PathBuilder {
    /// Create a new path builder
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Add a left sibling to the path
    pub fn add_left(mut self, hash: DataHash) -> Self {
        self.elements
            .push(PathElement::new(PathDirection::Left, hash));
        self
    }

    /// Add a right sibling to the path
    pub fn add_right(mut self, hash: DataHash) -> Self {
        self.elements
            .push(PathElement::new(PathDirection::Right, hash));
        self
    }

    /// Add an element to the path
    pub fn add_element(mut self, element: PathElement) -> Self {
        self.elements.push(element);
        self
    }

    /// Build the final path
    pub fn build(self, leaf_index: BigInt) -> MerkleTreePath {
        MerkleTreePath::new(self.elements, leaf_index)
    }
}

impl Default for PathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_computation() {
        let leaf_hash = DataHash::sha256(vec![1, 2, 3]);

        let path = PathBuilder::new()
            .add_left(DataHash::sha256(vec![4, 5, 6]))
            .add_right(DataHash::sha256(vec![7, 8, 9]))
            .build(BigInt::from(5));

        let root = path.compute_root(&leaf_hash);
        assert_eq!(root.data().len(), 32);
    }

    #[test]
    fn test_path_verification() {
        let leaf_hash = DataHash::sha256(vec![1]);
        let sibling_hash = DataHash::sha256(vec![2]);

        let expected_root = sha256_all(&[&leaf_hash.imprint(), &sibling_hash.imprint()]);

        let path = PathBuilder::new()
            .add_right(sibling_hash)
            .build(BigInt::from(0));

        assert!(path.verify(&leaf_hash, &expected_root));

        // Test with wrong leaf
        let wrong_leaf = DataHash::sha256(vec![3]);
        assert!(!path.verify(&wrong_leaf, &expected_root));
    }

    #[test]
    fn test_common_prefix() {
        let path1 = vec![
            PathElement::new(PathDirection::Left, DataHash::sha256(vec![1])),
            PathElement::new(PathDirection::Right, DataHash::sha256(vec![2])),
            PathElement::new(PathDirection::Left, DataHash::sha256(vec![3])),
        ];

        let path2 = vec![
            PathElement::new(PathDirection::Left, DataHash::sha256(vec![1])),
            PathElement::new(PathDirection::Right, DataHash::sha256(vec![2])),
            PathElement::new(PathDirection::Right, DataHash::sha256(vec![4])),
        ];

        let common = CommonPath::find_common_prefix(&path1, &path2);
        assert_eq!(common.len(), 2);
    }

    #[test]
    fn test_divergence_depth() {
        let index1 = BigInt::from(0b1100);
        let index2 = BigInt::from(0b1000);

        let depth = CommonPath::divergence_depth(&index1, &index2);
        assert_eq!(depth, 256 - 3); // Differ at bit position 2 (from right)
    }

    #[test]
    fn test_sibling_detection() {
        let path1 = PathBuilder::new()
            .add_left(DataHash::sha256(vec![1]))
            .build(BigInt::from(0));

        let path2 = PathBuilder::new()
            .add_left(DataHash::sha256(vec![1]))
            .build(BigInt::from(1));

        assert!(CommonPath::are_siblings(&path1, &path2));

        let path3 = PathBuilder::new()
            .add_left(DataHash::sha256(vec![1]))
            .build(BigInt::from(2));

        assert!(!CommonPath::are_siblings(&path1, &path3));
    }
}
