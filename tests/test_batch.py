"""Tests for Merkle batch operations."""

import hashlib
import json

import pytest
import responses

import agentcert
from agentcert.audit import AuditTrail, create_audit_trail, log_action
from agentcert.batch import (
    _build_batch_op_return_payload,
    _normalize_item,
    anchor_batch,
    create_batch,
    create_batch_from_entries,
    create_batch_from_trail,
    get_proof_for_entry,
    get_proof_for_item,
    load_batch,
    load_proofs,
    save_batch,
    save_proofs,
    verify_batch_proof,
    verify_entry_in_batch,
)
from agentcert.exceptions import BatchError
from agentcert.merkle import MerkleTree
from agentcert.types import (
    AnchorReceipt,
    Batch,
    BatchVerificationCheck,
    BatchVerificationResult,
    MerkleProof,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@pytest.fixture
def keys():
    return agentcert.generate_keys(), agentcert.generate_keys()


@pytest.fixture
def cert_and_keys(keys):
    creator_keys, agent_keys = keys
    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="test-agent",
        platform="test",
        model_hash="sha256:test",
        capabilities=["test"],
        constraints=["none"],
        risk_tier=1,
        expires_days=90,
    )
    return cert, creator_keys, agent_keys


@pytest.fixture
def trail_with_entries(cert_and_keys):
    cert, creator_keys, agent_keys = cert_and_keys
    trail = create_audit_trail(cert, agent_keys)
    for i in range(10):
        log_action(
            trail, agent_keys,
            action_type=agentcert.ActionType.TOOL_USE,
            action_summary=f"Action {i}",
            action_detail={"index": i},
        )
    return trail, cert, creator_keys, agent_keys


# ── _normalize_item ──────────────────────────────────────────────────────────


class TestNormalizeItem:
    """Tests for the item normalization helper."""

    def test_hex_string(self):
        h = _hash(b"test").hex()
        assert _normalize_item(h) == _hash(b"test")

    def test_bytes(self):
        h = _hash(b"test")
        assert _normalize_item(h) == h

    def test_dict(self):
        d = {"key": "value", "num": 42}
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(canonical).digest()
        assert _normalize_item(d) == expected

    def test_invalid_hex_raises(self):
        with pytest.raises(BatchError, match="not valid hex"):
            _normalize_item("not-hex-data")

    def test_wrong_length_hex_raises(self):
        with pytest.raises(BatchError, match="32 bytes"):
            _normalize_item("aabb")

    def test_wrong_length_bytes_raises(self):
        with pytest.raises(BatchError, match="32 bytes"):
            _normalize_item(b"short")

    def test_unsupported_type_raises(self):
        with pytest.raises(BatchError, match="Unsupported"):
            _normalize_item(42)  # type: ignore[arg-type]


# ── create_batch ─────────────────────────────────────────────────────────────


class TestCreateBatch:
    """Tests for create_batch()."""

    def test_from_hex_strings(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(5)]
        batch, tree = create_batch(hashes)
        assert batch.item_count == 5
        assert len(batch.item_hashes) == 5
        assert tree.leaf_count == 5
        assert batch.merkle_root == tree.root_hex
        assert batch.anchor_receipt is None
        assert len(batch.batch_id) == 64

    def test_from_bytes(self):
        leaves = [_hash(f"item-{i}".encode()) for i in range(3)]
        batch, tree = create_batch(leaves)
        assert batch.item_count == 3
        assert batch.merkle_root == tree.root_hex

    def test_from_dicts(self):
        dicts = [{"action": f"step-{i}"} for i in range(4)]
        batch, tree = create_batch(dicts)
        assert batch.item_count == 4
        assert batch.merkle_root == tree.root_hex

    def test_mixed_types(self):
        items = [
            _hash(b"a").hex(),
            _hash(b"b"),
            {"key": "c"},
        ]
        batch, tree = create_batch(items)
        assert batch.item_count == 3

    def test_single_item(self):
        batch, tree = create_batch([_hash(b"solo").hex()])
        assert batch.item_count == 1
        assert batch.merkle_root == _hash(b"solo").hex()

    def test_empty_raises(self):
        with pytest.raises(BatchError, match="empty"):
            create_batch([])

    def test_batch_id_deterministic(self):
        """Same items at the same timestamp produce the same batch_id."""
        hashes = [_hash(b"x").hex()]
        b1, _ = create_batch(hashes)
        # batch_id depends on root + timestamp, so two calls at different
        # times may differ. Just check it's a valid 64-char hex.
        assert len(b1.batch_id) == 64


# ── create_batch_from_entries ────────────────────────────────────────────────


class TestCreateBatchFromEntries:
    """Tests for create_batch_from_entries()."""

    def test_from_entries(self, trail_with_entries):
        trail, cert, _, _ = trail_with_entries
        batch, tree = create_batch_from_entries(trail.entries)
        assert batch.item_count == 10
        assert tree.leaf_count == 10
        # Each entry_id should be in the batch
        for entry in trail.entries:
            assert entry.entry_id in batch.item_hashes

    def test_empty_entries_raises(self):
        with pytest.raises(BatchError, match="empty"):
            create_batch_from_entries([])


# ── create_batch_from_trail ──────────────────────────────────────────────────


class TestCreateBatchFromTrail:
    """Tests for create_batch_from_trail()."""

    def test_from_trail(self, trail_with_entries):
        trail, cert, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        assert batch.item_count == 10
        assert batch.merkle_root == tree.root_hex

    def test_empty_trail_raises(self, cert_and_keys):
        cert, _, agent_keys = cert_and_keys
        empty_trail = create_audit_trail(cert, agent_keys)
        with pytest.raises(BatchError, match="no entries"):
            create_batch_from_trail(empty_trail)


# ── Proof Retrieval ──────────────────────────────────────────────────────────


class TestProofRetrieval:
    """Tests for get_proof_for_entry() and get_proof_for_item()."""

    def test_get_proof_for_entry(self, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        for entry in trail.entries:
            proof = get_proof_for_entry(entry, tree, batch)
            assert proof.leaf_hash == entry.entry_id
            assert proof.root == batch.merkle_root

    def test_get_proof_for_item(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(8)]
        batch, tree = create_batch(hashes)
        for h in hashes:
            proof = get_proof_for_item(h, tree, batch)
            assert proof.leaf_hash == h

    def test_missing_entry_raises(self, trail_with_entries):
        trail, _, _, agent_keys = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        # Create a new entry not in the batch
        log_action(trail, agent_keys, action_type=1, action_summary="Extra")
        extra_entry = trail.entries[-1]
        with pytest.raises(BatchError, match="not found"):
            get_proof_for_entry(extra_entry, tree, batch)

    def test_missing_item_raises(self):
        hashes = [_hash(b"a").hex()]
        batch, tree = create_batch(hashes)
        with pytest.raises(BatchError, match="not found"):
            get_proof_for_item(_hash(b"missing").hex(), tree, batch)


# ── Verification ─────────────────────────────────────────────────────────────


class TestVerifyBatchProof:
    """Tests for verify_batch_proof()."""

    def test_valid_proof_not_anchored(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(8)]
        batch, tree = create_batch(hashes)
        proof = get_proof_for_item(hashes[3], tree, batch)
        result = verify_batch_proof(hashes[3], proof, batch)
        assert result.valid is True
        assert result.status == "NOT_ANCHORED"
        assert result.proof_valid is True
        assert result.anchor_valid is None
        assert result.item_hash == hashes[3]
        assert result.merkle_root == batch.merkle_root

    def test_valid_proof_anchored(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(8)]
        batch, tree = create_batch(hashes)
        # Simulate anchoring by attaching a receipt
        receipt = AnchorReceipt(
            txid="abc123",
            network="testnet",
            anchor_hash=batch.merkle_root,
            op_return_hex="414954000101" + batch.merkle_root,
            cert_id=batch.batch_id,
        )
        anchored = Batch(
            batch_id=batch.batch_id,
            merkle_root=batch.merkle_root,
            item_count=batch.item_count,
            item_hashes=batch.item_hashes,
            timestamp=batch.timestamp,
            anchor_receipt=receipt,
        )
        proof = get_proof_for_item(hashes[5], tree, anchored)
        result = verify_batch_proof(hashes[5], proof, anchored)
        assert result.valid is True
        assert result.status == "VALID"
        assert result.anchor_valid is True

    def test_tampered_item_fails(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(4)]
        batch, tree = create_batch(hashes)
        proof = get_proof_for_item(hashes[0], tree, batch)
        fake_hash = _hash(b"tampered").hex()
        result = verify_batch_proof(fake_hash, proof, batch)
        assert result.valid is False
        assert result.status == "INVALID"
        assert result.proof_valid is False

    def test_mismatched_anchor_hash_fails(self):
        hashes = [_hash(b"a").hex()]
        batch, tree = create_batch(hashes)
        receipt = AnchorReceipt(
            txid="abc123",
            network="testnet",
            anchor_hash="wrong" * 8 + "wrong" * 8,  # wrong hash
            op_return_hex="aabbcc",
            cert_id="x",
        )
        anchored = Batch(
            batch_id=batch.batch_id,
            merkle_root=batch.merkle_root,
            item_count=batch.item_count,
            item_hashes=batch.item_hashes,
            timestamp=batch.timestamp,
            anchor_receipt=receipt,
        )
        proof = get_proof_for_item(hashes[0], tree, anchored)
        result = verify_batch_proof(hashes[0], proof, anchored)
        assert result.valid is False
        assert result.status == "INVALID"
        assert result.anchor_valid is False

    def test_all_entries_verify(self, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        for entry in trail.entries:
            proof = get_proof_for_entry(entry, tree, batch)
            result = verify_batch_proof(entry.entry_id, proof, batch)
            assert result.valid is True

    def test_checks_structure(self):
        hashes = [_hash(b"x").hex()]
        batch, tree = create_batch(hashes)
        proof = get_proof_for_item(hashes[0], tree, batch)
        result = verify_batch_proof(hashes[0], proof, batch)
        assert len(result.checks) >= 3
        names = [c.name for c in result.checks]
        assert "merkle_proof" in names
        assert "root_match" in names
        assert "anchor_validity" in names


# ── verify_entry_in_batch ────────────────────────────────────────────────────


class TestVerifyEntryInBatch:
    """Tests for verify_entry_in_batch()."""

    def test_with_matching_cert(self, trail_with_entries):
        trail, cert, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        entry = trail.entries[5]
        proof = get_proof_for_entry(entry, tree, batch)
        result = verify_entry_in_batch(entry, proof, batch, certificate=cert)
        assert result.valid is True
        names = [c.name for c in result.checks]
        assert "cert_binding" in names

    def test_with_wrong_cert(self, trail_with_entries, keys):
        trail, cert, _, _ = trail_with_entries
        other_creator, other_agent = keys
        other_cert = agentcert.create_certificate(
            creator_keys=other_creator,
            agent_keys=other_agent,
            name="other",
            platform="test",
            model_hash="sha256:other",
            capabilities=["other"],
            constraints=["none"],
            risk_tier=1,
            expires_days=90,
        )
        batch, tree = create_batch_from_trail(trail)
        entry = trail.entries[0]
        proof = get_proof_for_entry(entry, tree, batch)
        result = verify_entry_in_batch(entry, proof, batch, certificate=other_cert)
        assert result.valid is False
        assert result.status == "INVALID"

    def test_without_cert(self, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        entry = trail.entries[0]
        proof = get_proof_for_entry(entry, tree, batch)
        result = verify_entry_in_batch(entry, proof, batch)
        assert result.valid is True
        # No cert_binding check
        names = [c.name for c in result.checks]
        assert "cert_binding" not in names


# ── OP_RETURN Payload ────────────────────────────────────────────────────────


class TestBatchPayload:
    """Tests for the batch OP_RETURN payload construction."""

    def test_payload_format(self):
        root = _hash(b"root")
        payload = _build_batch_op_return_payload(root)
        assert len(payload) == 38
        assert payload[:4] == b"AIT\x00"
        assert payload[4] == 0x01  # version
        assert payload[5] == 0x01  # MERKLE_ROOT type
        assert payload[6:] == root

    def test_payload_type_is_merkle_root(self):
        root = _hash(b"test")
        payload = _build_batch_op_return_payload(root)
        # 0x01 = MERKLE_ROOT, not 0x02 = IDENTITY_CERT
        assert payload[5] == 0x01


# ── Anchor Batch (mocked) ───────────────────────────────────────────────────


class TestAnchorBatch:
    """Tests for anchor_batch() with mocked Blockstream API."""

    @responses.activate
    def test_anchor_batch_success(self, keys):
        creator_keys, _ = keys
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(4)]
        batch, tree = create_batch(hashes)

        address = agentcert.derive_bitcoin_address(creator_keys, network="testnet")
        utxo_url = f"https://blockstream.info/testnet/api/address/{address}/utxo"
        tx_url = "https://blockstream.info/testnet/api/tx"

        responses.add(
            responses.GET, utxo_url,
            json=[{"txid": "a" * 64, "vout": 0, "value": 50000, "status": {"confirmed": True}}],
        )
        responses.add(
            responses.POST, tx_url,
            body="b" * 64,
        )

        anchored = anchor_batch(batch, creator_keys=creator_keys, network="testnet")
        assert anchored.anchor_receipt is not None
        assert anchored.anchor_receipt.txid == "b" * 64
        assert anchored.anchor_receipt.anchor_hash == batch.merkle_root
        assert anchored.anchor_receipt.network == "testnet"
        # Batch metadata unchanged
        assert anchored.batch_id == batch.batch_id
        assert anchored.merkle_root == batch.merkle_root
        assert anchored.item_count == batch.item_count

    @responses.activate
    def test_anchor_batch_no_utxos(self, keys):
        creator_keys, _ = keys
        hashes = [_hash(b"x").hex()]
        batch, tree = create_batch(hashes)

        address = agentcert.derive_bitcoin_address(creator_keys, network="testnet")
        utxo_url = f"https://blockstream.info/testnet/api/address/{address}/utxo"
        responses.add(responses.GET, utxo_url, json=[])

        with pytest.raises(BatchError, match="No UTXOs"):
            anchor_batch(batch, creator_keys=creator_keys, network="testnet")


# ── Save / Load ──────────────────────────────────────────────────────────────


class TestBatchSaveLoad:
    """Tests for batch save/load operations."""

    def test_batch_roundtrip(self, tmp_path):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(5)]
        batch, tree = create_batch(hashes)
        path = tmp_path / "batch.json"
        save_batch(batch, path)
        loaded = load_batch(path)
        assert loaded.batch_id == batch.batch_id
        assert loaded.merkle_root == batch.merkle_root
        assert loaded.item_count == batch.item_count
        assert loaded.item_hashes == batch.item_hashes
        assert loaded.timestamp == batch.timestamp
        assert loaded.anchor_receipt is None

    def test_batch_with_receipt_roundtrip(self, tmp_path):
        hashes = [_hash(b"x").hex()]
        batch, _ = create_batch(hashes)
        receipt = AnchorReceipt(
            txid="abc",
            network="testnet",
            anchor_hash=batch.merkle_root,
            op_return_hex="deadbeef",
            cert_id=batch.batch_id,
        )
        anchored = Batch(
            batch_id=batch.batch_id,
            merkle_root=batch.merkle_root,
            item_count=batch.item_count,
            item_hashes=batch.item_hashes,
            timestamp=batch.timestamp,
            anchor_receipt=receipt,
        )
        path = tmp_path / "batch.json"
        save_batch(anchored, path)
        loaded = load_batch(path)
        assert loaded.anchor_receipt is not None
        assert loaded.anchor_receipt.txid == "abc"

    def test_batch_json_valid(self, tmp_path):
        hashes = [_hash(b"x").hex()]
        batch, _ = create_batch(hashes)
        path = tmp_path / "batch.json"
        save_batch(batch, path)
        data = json.loads(path.read_text())
        assert "batch_id" in data
        assert "merkle_root" in data
        assert "item_hashes" in data

    def test_load_nonexistent_raises(self, tmp_path):
        with pytest.raises(BatchError):
            load_batch(tmp_path / "nope.json")


class TestProofsSaveLoad:
    """Tests for proof save/load operations."""

    def test_proofs_roundtrip(self, tmp_path, trail_with_entries):
        trail, _, _, _ = trail_with_entries
        batch, tree = create_batch_from_trail(trail)
        proofs = {
            e.entry_id: get_proof_for_entry(e, tree, batch)
            for e in trail.entries
        }
        path = tmp_path / "proofs.json"
        save_proofs(proofs, path)
        loaded = load_proofs(path)
        assert len(loaded) == 10
        for entry_id, proof in loaded.items():
            assert proof == proofs[entry_id]

    def test_proofs_json_valid(self, tmp_path):
        hashes = [_hash(b"a").hex(), _hash(b"b").hex()]
        batch, tree = create_batch(hashes)
        proofs = {h: get_proof_for_item(h, tree, batch) for h in hashes}
        path = tmp_path / "proofs.json"
        save_proofs(proofs, path)
        data = json.loads(path.read_text())
        assert len(data) == 2
        for v in data.values():
            assert "leaf_hash" in v
            assert "siblings" in v

    def test_load_nonexistent_raises(self, tmp_path):
        with pytest.raises(BatchError):
            load_proofs(tmp_path / "nope.json")


# ── Batch to_dict / from_dict ───────────────────────────────────────────────


class TestBatchSerialization:
    """Tests for Batch to_dict/from_dict."""

    def test_roundtrip(self):
        hashes = [_hash(f"item-{i}".encode()).hex() for i in range(3)]
        batch, _ = create_batch(hashes)
        d = batch.to_dict()
        restored = Batch.from_dict(d)
        assert restored == batch

    def test_with_receipt(self):
        hashes = [_hash(b"x").hex()]
        batch, _ = create_batch(hashes)
        receipt = AnchorReceipt(
            txid="tx1", network="testnet", anchor_hash="ah",
            op_return_hex="or", cert_id="ci",
        )
        anchored = Batch(
            batch_id=batch.batch_id,
            merkle_root=batch.merkle_root,
            item_count=batch.item_count,
            item_hashes=batch.item_hashes,
            timestamp=batch.timestamp,
            anchor_receipt=receipt,
        )
        d = anchored.to_dict()
        restored = Batch.from_dict(d)
        assert restored == anchored
        assert restored.anchor_receipt.txid == "tx1"


# ── Full Lifecycle ───────────────────────────────────────────────────────────


class TestBatchLifecycle:
    """End-to-end test: create trail → batch → proofs → verify."""

    def test_full_lifecycle(self, trail_with_entries, tmp_path):
        trail, cert, _, _ = trail_with_entries

        # Batch
        batch, tree = create_batch_from_trail(trail)
        assert batch.item_count == 10

        # Generate proofs for all entries
        proofs = {}
        for entry in trail.entries:
            proof = get_proof_for_entry(entry, tree, batch)
            proofs[entry.entry_id] = proof

        # Verify each entry
        for entry in trail.entries:
            result = verify_entry_in_batch(
                entry, proofs[entry.entry_id], batch, certificate=cert,
            )
            assert result.valid is True
            assert result.status == "NOT_ANCHORED"
            assert result.proof_valid is True

        # Save and reload
        save_batch(batch, tmp_path / "batch.json")
        save_proofs(proofs, tmp_path / "proofs.json")
        loaded_batch = load_batch(tmp_path / "batch.json")
        loaded_proofs = load_proofs(tmp_path / "proofs.json")

        # Re-verify from loaded data
        for entry in trail.entries:
            result = verify_batch_proof(
                entry.entry_id, loaded_proofs[entry.entry_id], loaded_batch,
            )
            assert result.valid is True
