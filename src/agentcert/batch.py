"""Batch creation, Merkle anchoring, and proof verification.

Multiple audit entries (from one or many agents) get batched into a Merkle
tree. The Merkle root gets anchored to Bitcoin in a single transaction.
Any individual entry is then provable against the on-chain root via its
Merkle proof.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from agentcert.anchor import (
    AIT_MAGIC,
    AIT_VERSION,
    _broadcast_tx,
    _build_segwit_tx,
    _fetch_utxos,
    _hash160,
    build_op_return_script,
    derive_bitcoin_address,
)
from agentcert.audit import AuditTrail
from agentcert.exceptions import BatchError
from agentcert.merkle import MerkleTree
from agentcert.types import (
    AnchorReceipt,
    AuditEntry,
    Batch,
    BatchVerificationCheck,
    BatchVerificationResult,
    Certificate,
    KeyPair,
    MerkleProof,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _normalize_item(item: str | bytes | dict[str, Any]) -> bytes:
    """Normalize an item to a 32-byte SHA-256 leaf hash.

    Args:
        item: A hex string (64 chars = 32 bytes), raw bytes (32 bytes),
            or a dict (serialized to canonical JSON, then hashed).

    Returns:
        32-byte SHA-256 hash.

    Raises:
        BatchError: If the item cannot be normalized.
    """
    if isinstance(item, bytes):
        if len(item) == 32:
            return item
        raise BatchError(f"bytes item must be 32 bytes, got {len(item)}")
    if isinstance(item, str):
        try:
            raw = bytes.fromhex(item)
        except ValueError:
            raise BatchError(f"string item is not valid hex: {item[:32]}...")
        if len(raw) != 32:
            raise BatchError(f"hex string must decode to 32 bytes, got {len(raw)}")
        return raw
    if isinstance(item, dict):
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).digest()
    raise BatchError(f"Unsupported item type: {type(item).__name__}")


def _generate_batch_id(merkle_root: str, timestamp: int) -> str:
    """Generate a deterministic batch_id from root + timestamp."""
    seed = f"{merkle_root}:{timestamp}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


# ── Batch Creation ───────────────────────────────────────────────────────────


def create_batch(items: list[str | bytes | dict[str, Any]]) -> tuple[Batch, MerkleTree]:
    """Create a batch from a list of items.

    Items can be:
    - hex strings (64 chars, treated as pre-computed 32-byte hashes)
    - bytes (32 bytes, treated as pre-computed hashes)
    - dicts (serialized to canonical JSON, then SHA-256 hashed)

    Args:
        items: List of items to batch. Must have at least 1 item.

    Returns:
        A tuple of (Batch metadata, MerkleTree for proof generation).

    Raises:
        BatchError: If the items list is empty or contains invalid items.
    """
    if not items:
        raise BatchError("Cannot create batch from empty list")

    leaves = [_normalize_item(item) for item in items]
    tree = MerkleTree(leaves)

    now = int(time.time())
    batch_id = _generate_batch_id(tree.root_hex, now)

    batch = Batch(
        batch_id=batch_id,
        merkle_root=tree.root_hex,
        item_count=len(items),
        item_hashes=tuple(leaf.hex() for leaf in leaves),
        timestamp=now,
        anchor_receipt=None,
    )

    return batch, tree


def create_batch_from_entries(entries: list[AuditEntry]) -> tuple[Batch, MerkleTree]:
    """Create a batch from a list of audit entries.

    Each entry's entry_id (which is SHA-256 of its body) is used as the
    leaf hash.

    Args:
        entries: List of audit entries. Must have at least 1 entry.

    Returns:
        A tuple of (Batch metadata, MerkleTree for proof generation).

    Raises:
        BatchError: If the entries list is empty.
    """
    if not entries:
        raise BatchError("Cannot create batch from empty entries list")

    return create_batch([e.entry_id for e in entries])


def create_batch_from_trail(trail: AuditTrail) -> tuple[Batch, MerkleTree]:
    """Create a batch from all entries in an audit trail.

    Args:
        trail: An audit trail with at least 1 entry.

    Returns:
        A tuple of (Batch metadata, MerkleTree for proof generation).

    Raises:
        BatchError: If the trail has no entries.
    """
    if not trail.entries:
        raise BatchError("Cannot create batch from trail with no entries")

    return create_batch_from_entries(trail.entries)


# ── Batch Anchoring ─────────────────────────────────────────────────────────


_MERKLE_ROOT_TYPE = b"\x01"
_DEFAULT_FEE_SATS = 1000


def _build_batch_op_return_payload(merkle_root: bytes) -> bytes:
    """Build the 38-byte AIT OP_RETURN payload for a Merkle root.

    Format: AIT\\x00 (4) + version 0x01 (1) + type 0x01 MERKLE_ROOT (1)
            + SHA-256 hash (32) = 38 bytes.

    Args:
        merkle_root: 32-byte Merkle root hash.

    Returns:
        38-byte payload.
    """
    payload = AIT_MAGIC + AIT_VERSION + _MERKLE_ROOT_TYPE + merkle_root
    assert len(payload) == 38, f"Payload must be 38 bytes, got {len(payload)}"
    return payload


def anchor_batch(
    batch: Batch,
    *,
    creator_keys: KeyPair,
    network: str = "testnet",
    fee_sats: int = _DEFAULT_FEE_SATS,
) -> Batch:
    """Anchor a batch's Merkle root to Bitcoin via an OP_RETURN transaction.

    Constructs an OP_RETURN payload with type 0x01 (MERKLE_ROOT) and the
    32-byte Merkle root. Uses the existing Bitcoin transaction infrastructure
    from anchor.py.

    Args:
        batch: The batch to anchor.
        creator_keys: Key pair for funding and signing the Bitcoin transaction.
        network: "testnet" or "mainnet".
        fee_sats: Transaction fee in satoshis (default: 1000).

    Returns:
        A new Batch with anchor_receipt set.

    Raises:
        BatchError: If anchoring fails.
    """
    try:
        merkle_root_bytes = bytes.fromhex(batch.merkle_root)
        payload = _build_batch_op_return_payload(merkle_root_bytes)
        or_script = build_op_return_script(payload)

        pubkey_bytes = bytes.fromhex(creator_keys.public_key_hex)
        pubkey_hash = _hash160(pubkey_bytes)
        address = derive_bitcoin_address(creator_keys, network=network)

        utxos = _fetch_utxos(address, network)
        if not utxos:
            raise BatchError(
                f"No UTXOs found for {address} on {network}. "
                f"Fund this address first."
            )

        utxo = None
        for u in utxos:
            if u["value"] >= fee_sats:
                utxo = u
                break

        if utxo is None:
            raise BatchError(
                f"No UTXO with sufficient balance (>= {fee_sats} sats) "
                f"found for {address} on {network}."
            )

        signed_tx = _build_segwit_tx(
            utxo_txid_hex=utxo["txid"],
            utxo_vout=utxo["vout"],
            utxo_value_sats=utxo["value"],
            private_key=creator_keys.private_key,
            public_key_hex=creator_keys.public_key_hex,
            pubkey_hash=pubkey_hash,
            op_return_script=or_script,
            change_value_sats=utxo["value"] - fee_sats,
        )

        txid = _broadcast_tx(signed_tx.hex(), network)
    except BatchError:
        raise
    except Exception as exc:
        raise BatchError(f"Failed to anchor batch: {exc}") from exc

    receipt = AnchorReceipt(
        txid=txid,
        network=network,
        anchor_hash=batch.merkle_root,
        op_return_hex=payload.hex(),
        cert_id=batch.batch_id,
    )

    return Batch(
        batch_id=batch.batch_id,
        merkle_root=batch.merkle_root,
        item_count=batch.item_count,
        item_hashes=batch.item_hashes,
        timestamp=batch.timestamp,
        anchor_receipt=receipt,
    )


# ── Proof Retrieval ──────────────────────────────────────────────────────────


def get_proof_for_item(
    item_hash: str,
    tree: MerkleTree,
    batch: Batch,
) -> MerkleProof:
    """Get the Merkle proof for a specific item hash in a batch.

    Args:
        item_hash: Hex string of the item's leaf hash.
        tree: The MerkleTree used to build the batch.
        batch: The batch containing the item.

    Returns:
        A MerkleProof for the item.

    Raises:
        BatchError: If the item is not in the batch.
    """
    try:
        index = list(batch.item_hashes).index(item_hash)
    except ValueError:
        raise BatchError(f"Item hash {item_hash[:16]}... not found in batch")

    return tree.get_proof(index)


def get_proof_for_entry(
    entry: AuditEntry,
    tree: MerkleTree,
    batch: Batch,
) -> MerkleProof:
    """Get the Merkle proof for a specific audit entry in a batch.

    Args:
        entry: The audit entry.
        tree: The MerkleTree used to build the batch.
        batch: The batch containing the entry.

    Returns:
        A MerkleProof for the entry.

    Raises:
        BatchError: If the entry is not in the batch.
    """
    return get_proof_for_item(entry.entry_id, tree, batch)


# ── Verification ─────────────────────────────────────────────────────────────


def verify_batch_proof(
    item_hash: str,
    proof: MerkleProof,
    batch: Batch,
) -> BatchVerificationResult:
    """Verify that an item is included in a batch.

    Checks:
    1. Merkle proof validity — recompute root from item + siblings.
    2. Root match — computed root matches batch's merkle_root.
    3. Anchor validity — batch's merkle_root matches on-chain data
       (only if batch has an anchor_receipt).

    Args:
        item_hash: Hex string of the item's leaf hash.
        proof: The Merkle proof for the item.
        batch: The batch to verify against.

    Returns:
        A BatchVerificationResult with status and checks.
    """
    checks: list[BatchVerificationCheck] = []

    # Check 1: Merkle proof validity
    try:
        leaf_bytes = bytes.fromhex(item_hash)
        root_bytes = bytes.fromhex(batch.merkle_root)
        proof_valid = MerkleTree.verify_proof(leaf_bytes, proof, root_bytes)
    except Exception as exc:
        proof_valid = False
        checks.append(BatchVerificationCheck(
            name="merkle_proof",
            passed=False,
            detail=f"Proof verification error: {exc}",
        ))
    else:
        checks.append(BatchVerificationCheck(
            name="merkle_proof",
            passed=proof_valid,
            detail="Merkle proof valid" if proof_valid else "Merkle proof invalid",
        ))

    # Check 2: Root match
    root_match = proof.root == batch.merkle_root
    checks.append(BatchVerificationCheck(
        name="root_match",
        passed=root_match,
        detail="Proof root matches batch merkle_root" if root_match
        else f"Root mismatch: proof={proof.root[:16]}... batch={batch.merkle_root[:16]}...",
    ))

    # Check 3: Anchor validity (if anchored)
    anchor_valid: bool | None = None
    if batch.anchor_receipt is not None:
        anchor_valid = batch.anchor_receipt.anchor_hash == batch.merkle_root
        checks.append(BatchVerificationCheck(
            name="anchor_validity",
            passed=anchor_valid,
            detail="Anchor hash matches merkle_root" if anchor_valid
            else "Anchor hash does not match merkle_root",
        ))
    else:
        checks.append(BatchVerificationCheck(
            name="anchor_validity",
            passed=True,
            detail="Batch not yet anchored (skipped)",
        ))

    all_passed = proof_valid and root_match and (anchor_valid is not False)

    if not all_passed:
        status = "INVALID"
    elif batch.anchor_receipt is None:
        status = "NOT_ANCHORED"
    else:
        status = "VALID"

    return BatchVerificationResult(
        valid=all_passed,
        status=status,
        item_hash=item_hash,
        merkle_root=batch.merkle_root,
        proof_valid=proof_valid,
        anchor_valid=anchor_valid,
        checks=tuple(checks),
    )


def verify_entry_in_batch(
    entry: AuditEntry,
    proof: MerkleProof,
    batch: Batch,
    certificate: Certificate | None = None,
) -> BatchVerificationResult:
    """Verify an audit entry is included in a batch.

    Runs the standard batch proof verification. Optionally also checks
    that the entry's cert_id matches the provided certificate.

    Args:
        entry: The audit entry to verify.
        proof: The Merkle proof for the entry.
        batch: The batch to verify against.
        certificate: Optional certificate for binding check.

    Returns:
        A BatchVerificationResult with status and checks.
    """
    result = verify_batch_proof(entry.entry_id, proof, batch)

    if certificate is not None:
        binding_ok = entry.cert_id == certificate.cert_id
        extra_check = BatchVerificationCheck(
            name="cert_binding",
            passed=binding_ok,
            detail="Entry cert_id matches certificate" if binding_ok
            else f"cert_id mismatch: entry={entry.cert_id[:16]}... cert={certificate.cert_id[:16]}...",
        )

        all_valid = result.valid and binding_ok
        status = result.status if binding_ok else "INVALID"

        return BatchVerificationResult(
            valid=all_valid,
            status=status,
            item_hash=result.item_hash,
            merkle_root=result.merkle_root,
            proof_valid=result.proof_valid,
            anchor_valid=result.anchor_valid,
            checks=result.checks + (extra_check,),
        )

    return result


# ── Save / Load ──────────────────────────────────────────────────────────────


def save_batch(batch: Batch, path: str | Path) -> None:
    """Save batch metadata to a JSON file.

    Args:
        batch: The batch to save.
        path: File path to write to.

    Raises:
        BatchError: If saving fails.
    """
    try:
        Path(path).write_text(
            json.dumps(batch.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise BatchError(f"Failed to save batch to {path}: {exc}") from exc


def load_batch(path: str | Path) -> Batch:
    """Load batch metadata from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        The loaded Batch.

    Raises:
        BatchError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return Batch.from_dict(data)
    except BatchError:
        raise
    except Exception as exc:
        raise BatchError(f"Failed to load batch from {path}: {exc}") from exc


def save_proofs(proofs: dict[str, MerkleProof], path: str | Path) -> None:
    """Save a mapping of item_hash -> MerkleProof to a JSON file.

    Args:
        proofs: Dict mapping item hashes to their Merkle proofs.
        path: File path to write to.

    Raises:
        BatchError: If saving fails.
    """
    try:
        data = {k: v.to_dict() for k, v in proofs.items()}
        Path(path).write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise BatchError(f"Failed to save proofs to {path}: {exc}") from exc


def load_proofs(path: str | Path) -> dict[str, MerkleProof]:
    """Load proofs from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        Dict mapping item hashes to their Merkle proofs.

    Raises:
        BatchError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {k: MerkleProof.from_dict(v) for k, v in data.items()}
    except BatchError:
        raise
    except Exception as exc:
        raise BatchError(f"Failed to load proofs from {path}: {exc}") from exc
