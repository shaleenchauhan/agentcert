"""Binary Merkle tree for batching multiple hashes into a single root.

Standard SHA-256 binary Merkle tree. Leaves are 32-byte hashes passed in
directly. Internal nodes are SHA-256(left_child + right_child). If a level
has an odd number of nodes the last node is duplicated.
"""

from __future__ import annotations

import hashlib

from agentcert.exceptions import BatchError
from agentcert.types import MerkleProof


class MerkleTree:
    """Binary Merkle tree for batching multiple hashes into a single root.

    Args:
        leaves: List of 32-byte SHA-256 hashes. Must have at least 1 leaf.
            If odd number of leaves, the last leaf is duplicated at each
            level as needed.

    Raises:
        BatchError: If the leaves list is empty or contains invalid hashes.
    """

    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise BatchError("Cannot build Merkle tree from empty list")

        for i, leaf in enumerate(leaves):
            if not isinstance(leaf, bytes) or len(leaf) != 32:
                raise BatchError(
                    f"Leaf {i} must be 32 bytes, got {type(leaf).__name__} "
                    f"of length {len(leaf) if isinstance(leaf, bytes) else '?'}"
                )

        self._leaf_count = len(leaves)
        self._levels: list[list[bytes]] = [list(leaves)]
        self._build()

    def _build(self) -> None:
        """Build the tree levels from leaves up to the root."""
        level = self._levels[0]
        while len(level) > 1:
            next_level: list[bytes] = []
            # If odd, duplicate the last node
            if len(level) % 2 != 0:
                level = level + [level[-1]]
            for i in range(0, len(level), 2):
                next_level.append(self.hash_pair(level[i], level[i + 1]))
            self._levels.append(next_level)
            level = next_level

    @property
    def root(self) -> bytes:
        """The 32-byte Merkle root hash."""
        return self._levels[-1][0]

    @property
    def root_hex(self) -> str:
        """The Merkle root as a hex string."""
        return self.root.hex()

    @property
    def leaf_count(self) -> int:
        """Number of original leaves (before any duplication)."""
        return self._leaf_count

    def get_proof(self, index: int) -> MerkleProof:
        """Get the inclusion proof for a leaf at the given index.

        Args:
            index: Zero-based index of the leaf.

        Returns:
            A MerkleProof with sibling hashes and directions needed to
            recompute the root from the leaf.

        Raises:
            BatchError: If the index is out of range.
        """
        if index < 0 or index >= self._leaf_count:
            raise BatchError(
                f"Leaf index {index} out of range [0, {self._leaf_count})"
            )

        siblings: list[str] = []
        directions: list[str] = []
        idx = index

        for level_num in range(len(self._levels) - 1):
            level = self._levels[level_num]
            # Pad odd levels for sibling lookup
            if len(level) % 2 != 0:
                level = level + [level[-1]]

            if idx % 2 == 0:
                # Current node is on the left, sibling is on the right
                sibling_idx = idx + 1
                directions.append("right")
            else:
                # Current node is on the right, sibling is on the left
                sibling_idx = idx - 1
                directions.append("left")

            siblings.append(level[sibling_idx].hex())
            idx = idx // 2

        leaf_hash = self._levels[0][index].hex()
        return MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=index,
            siblings=tuple(siblings),
            directions=tuple(directions),
            root=self.root_hex,
        )

    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Hash two 32-byte values together: SHA-256(left + right).

        Args:
            left: Left child hash (32 bytes).
            right: Right child hash (32 bytes).

        Returns:
            32-byte SHA-256 digest.
        """
        return hashlib.sha256(left + right).digest()

    @staticmethod
    def verify_proof(leaf_hash: bytes, proof: MerkleProof, root: bytes) -> bool:
        """Verify that a leaf is included in the tree with the given root.

        Recomputes the root from the leaf and proof siblings, then compares
        to the expected root.

        Args:
            leaf_hash: The 32-byte leaf hash to verify.
            proof: The Merkle proof (siblings + directions).
            root: The expected 32-byte Merkle root.

        Returns:
            True if the proof is valid, False otherwise.
        """
        current = leaf_hash
        for sibling_hex, direction in zip(proof.siblings, proof.directions):
            sibling = bytes.fromhex(sibling_hex)
            if direction == "left":
                current = MerkleTree.hash_pair(sibling, current)
            else:
                current = MerkleTree.hash_pair(current, sibling)
        return current == root
