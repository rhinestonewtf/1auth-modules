use crate::keccak::keccak256;

/// Sorted-pair hash matching Solady's MerkleProofLib.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if a < b {
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
    } else {
        buf[..32].copy_from_slice(b);
        buf[32..].copy_from_slice(a);
    }
    keccak256(&buf)
}

pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    pub fn build(&self) -> Result<([u8; 32], Vec<Vec<[u8; 32]>>), String> {
        let n = self.leaves.len();
        if n == 0 {
            return Err("empty leaves".to_string());
        }
        if n == 1 {
            return Ok((self.leaves[0], vec![vec![]]));
        }

        let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();
        layers.push(self.leaves.clone());

        let mut current = self.leaves.clone();
        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_pair(&current[i], &current[i + 1]));
                } else {
                    next.push(current[i]);
                }
                i += 2;
            }
            layers.push(next.clone());
            current = next;
        }

        let root = current[0];
        let mut proofs = Vec::with_capacity(n);
        for leaf_idx in 0..n {
            let mut proof = Vec::new();
            let mut idx = leaf_idx;
            for layer in layers.iter().take(layers.len() - 1) {
                let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                if sibling_idx < layer.len() {
                    proof.push(layer[sibling_idx]);
                }
                idx /= 2;
            }
            proofs.push(proof);
        }

        Ok((root, proofs))
    }

    pub fn verify(proof: &[[u8; 32]], root: &[u8; 32], leaf: &[u8; 32]) -> bool {
        let mut hash = *leaf;
        for sibling in proof {
            hash = hash_pair(&hash, sibling);
        }
        hash == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf() {
        let leaf = keccak256(b"hello");
        let tree = MerkleTree::new(vec![leaf]);
        let (root, proofs) = tree.build().unwrap();
        assert_eq!(root, leaf);
        assert!(proofs[0].is_empty());
    }

    #[test]
    fn two_leaves() {
        let a = keccak256(b"leaf_a");
        let b = keccak256(b"leaf_b");
        let tree = MerkleTree::new(vec![a, b]);
        let (root, proofs) = tree.build().unwrap();
        assert!(MerkleTree::verify(&proofs[0], &root, &a));
        assert!(MerkleTree::verify(&proofs[1], &root, &b));
    }

    #[test]
    fn four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| keccak256(&[i])).collect();
        let tree = MerkleTree::new(leaves.clone());
        let (root, proofs) = tree.build().unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(MerkleTree::verify(&proofs[i], &root, leaf));
        }
    }

    #[test]
    fn odd_leaves() {
        let leaves: Vec<[u8; 32]> = (0..3u8).map(|i| keccak256(&[i])).collect();
        let tree = MerkleTree::new(leaves.clone());
        let (root, proofs) = tree.build().unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(MerkleTree::verify(&proofs[i], &root, leaf));
        }
    }
}
