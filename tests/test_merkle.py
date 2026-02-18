"""Tests for the Merkle tree implementation."""

import hashlib

import pytest

from agentcert.exceptions import BatchError
from agentcert.merkle import MerkleTree
from agentcert.types import MerkleProof


def _hash(data: bytes) -> bytes:
    """Shortcut for SHA-256."""
    return hashlib.sha256(data).digest()


def _make_leaves(n: int) -> list[bytes]:
    """Generate n deterministic 32-byte leaf hashes."""
    return [_hash(f"leaf-{i}".encode()) for i in range(n)]


# ── Construction ─────────────────────────────────────────────────────────────


class TestMerkleTreeConstruction:
    """Tests for building Merkle trees."""

    def test_single_leaf(self):
        leaves = _make_leaves(1)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 1
        # Root of a single-leaf tree is the leaf itself
        assert tree.root == leaves[0]

    def test_two_leaves(self):
        leaves = _make_leaves(2)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 2
        expected_root = MerkleTree.hash_pair(leaves[0], leaves[1])
        assert tree.root == expected_root

    def test_three_leaves(self):
        """Three leaves: last leaf duplicated to make 4, then paired."""
        leaves = _make_leaves(3)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 3
        h01 = MerkleTree.hash_pair(leaves[0], leaves[1])
        h22 = MerkleTree.hash_pair(leaves[2], leaves[2])  # duplicated
        expected_root = MerkleTree.hash_pair(h01, h22)
        assert tree.root == expected_root

    def test_four_leaves(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 4
        h01 = MerkleTree.hash_pair(leaves[0], leaves[1])
        h23 = MerkleTree.hash_pair(leaves[2], leaves[3])
        expected_root = MerkleTree.hash_pair(h01, h23)
        assert tree.root == expected_root

    def test_seven_leaves(self):
        leaves = _make_leaves(7)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 7
        # Just verify it doesn't error and produces a 32-byte root
        assert len(tree.root) == 32

    def test_eight_leaves(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 8
        assert len(tree.root) == 32

    def test_sixteen_leaves(self):
        leaves = _make_leaves(16)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 16
        assert len(tree.root) == 32

    def test_hundred_leaves(self):
        leaves = _make_leaves(100)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 100
        assert len(tree.root) == 32

    def test_thousand_leaves(self):
        leaves = _make_leaves(1000)
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 1000
        assert len(tree.root) == 32

    def test_empty_raises(self):
        with pytest.raises(BatchError, match="empty"):
            MerkleTree([])

    def test_invalid_leaf_length_raises(self):
        with pytest.raises(BatchError, match="32 bytes"):
            MerkleTree([b"short"])

    def test_invalid_leaf_type_raises(self):
        with pytest.raises(BatchError):
            MerkleTree(["not bytes"])  # type: ignore[list-item]


# ── Root Properties ──────────────────────────────────────────────────────────


class TestMerkleRoot:
    """Tests for root properties."""

    def test_root_hex(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        assert tree.root_hex == tree.root.hex()
        assert len(tree.root_hex) == 64

    def test_deterministic(self):
        """Same leaves always produce the same root."""
        leaves = _make_leaves(10)
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.root == tree2.root

    def test_different_leaves_different_root(self):
        tree1 = MerkleTree(_make_leaves(4))
        tree2 = MerkleTree([_hash(f"other-{i}".encode()) for i in range(4)])
        assert tree1.root != tree2.root

    def test_order_matters(self):
        leaves = _make_leaves(4)
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(list(reversed(leaves)))
        assert tree1.root != tree2.root


# ── hash_pair ────────────────────────────────────────────────────────────────


class TestHashPair:
    """Tests for the hash_pair static method."""

    def test_basic(self):
        a = _hash(b"a")
        b = _hash(b"b")
        result = MerkleTree.hash_pair(a, b)
        assert result == hashlib.sha256(a + b).digest()
        assert len(result) == 32

    def test_not_commutative(self):
        a = _hash(b"a")
        b = _hash(b"b")
        assert MerkleTree.hash_pair(a, b) != MerkleTree.hash_pair(b, a)


# ── Proof Generation ────────────────────────────────────────────────────────


class TestProofGeneration:
    """Tests for get_proof()."""

    def test_single_leaf_proof(self):
        leaves = _make_leaves(1)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        assert isinstance(proof, MerkleProof)
        assert proof.leaf_hash == leaves[0].hex()
        assert proof.leaf_index == 0
        assert proof.root == tree.root_hex
        assert len(proof.siblings) == 0
        assert len(proof.directions) == 0

    def test_two_leaf_proof(self):
        leaves = _make_leaves(2)
        tree = MerkleTree(leaves)
        proof0 = tree.get_proof(0)
        assert proof0.leaf_index == 0
        assert len(proof0.siblings) == 1
        assert proof0.siblings[0] == leaves[1].hex()
        assert proof0.directions[0] == "right"

        proof1 = tree.get_proof(1)
        assert proof1.leaf_index == 1
        assert proof1.siblings[0] == leaves[0].hex()
        assert proof1.directions[0] == "left"

    def test_four_leaf_proofs(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        for i in range(4):
            proof = tree.get_proof(i)
            assert proof.leaf_index == i
            assert len(proof.siblings) == 2  # log2(4)
            assert proof.root == tree.root_hex

    def test_proof_depth_for_powers_of_two(self):
        for n in [2, 4, 8, 16, 32]:
            leaves = _make_leaves(n)
            tree = MerkleTree(leaves)
            proof = tree.get_proof(0)
            import math
            expected_depth = int(math.log2(n))
            assert len(proof.siblings) == expected_depth

    def test_out_of_range_raises(self):
        tree = MerkleTree(_make_leaves(4))
        with pytest.raises(BatchError, match="out of range"):
            tree.get_proof(4)
        with pytest.raises(BatchError, match="out of range"):
            tree.get_proof(-1)

    def test_hundred_leaf_proofs(self):
        leaves = _make_leaves(100)
        tree = MerkleTree(leaves)
        for i in range(100):
            proof = tree.get_proof(i)
            assert proof.leaf_hash == leaves[i].hex()
            assert proof.root == tree.root_hex


# ── Proof Verification ──────────────────────────────────────────────────────


class TestProofVerification:
    """Tests for verify_proof()."""

    def test_valid_proofs_all_leaves(self):
        """Every leaf in a 16-leaf tree verifies correctly."""
        leaves = _make_leaves(16)
        tree = MerkleTree(leaves)
        for i in range(16):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, tree.root)

    def test_single_leaf_verifies(self):
        leaves = _make_leaves(1)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        assert MerkleTree.verify_proof(leaves[0], proof, tree.root)

    def test_odd_leaves_verify(self):
        """Trees with odd leaf counts (3, 5, 7) verify correctly."""
        for n in [3, 5, 7]:
            leaves = _make_leaves(n)
            tree = MerkleTree(leaves)
            for i in range(n):
                proof = tree.get_proof(i)
                assert MerkleTree.verify_proof(leaves[i], proof, tree.root)

    def test_thousand_leaf_sample_verify(self):
        leaves = _make_leaves(1000)
        tree = MerkleTree(leaves)
        # Verify a sample of indices
        for i in [0, 1, 499, 500, 998, 999]:
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, tree.root)

    def test_tampered_leaf_fails(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(3)
        fake_leaf = _hash(b"tampered")
        assert not MerkleTree.verify_proof(fake_leaf, proof, tree.root)

    def test_wrong_root_fails(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(3)
        wrong_root = _hash(b"wrong-root")
        assert not MerkleTree.verify_proof(leaves[3], proof, wrong_root)

    def test_tampered_sibling_fails(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        # Tamper with the first sibling
        tampered = MerkleProof(
            leaf_hash=proof.leaf_hash,
            leaf_index=proof.leaf_index,
            siblings=(_hash(b"tampered").hex(),) + proof.siblings[1:],
            directions=proof.directions,
            root=proof.root,
        )
        assert not MerkleTree.verify_proof(leaves[0], tampered, tree.root)

    def test_swapped_direction_fails(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        # Swap the first direction
        swapped_dir = "left" if proof.directions[0] == "right" else "right"
        tampered = MerkleProof(
            leaf_hash=proof.leaf_hash,
            leaf_index=proof.leaf_index,
            siblings=proof.siblings,
            directions=(swapped_dir,) + proof.directions[1:],
            root=proof.root,
        )
        assert not MerkleTree.verify_proof(leaves[0], tampered, tree.root)


# ── MerkleProof Serialization ───────────────────────────────────────────────


class TestMerkleProofSerialization:
    """Tests for MerkleProof to_dict/from_dict."""

    def test_roundtrip(self):
        leaves = _make_leaves(8)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(3)
        d = proof.to_dict()
        restored = MerkleProof.from_dict(d)
        assert restored == proof

    def test_dict_structure(self):
        leaves = _make_leaves(4)
        tree = MerkleTree(leaves)
        proof = tree.get_proof(1)
        d = proof.to_dict()
        assert set(d.keys()) == {"leaf_hash", "leaf_index", "siblings", "directions", "root"}
        assert isinstance(d["siblings"], list)
        assert isinstance(d["directions"], list)
