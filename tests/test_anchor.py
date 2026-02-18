"""Tests for agentcert.anchor — OP_RETURN construction and Bitcoin anchoring."""

import json

import pytest
import responses

from agentcert.keys import generate_keys
from agentcert.certificate import create_certificate
from agentcert.chain import revoke_certificate
from agentcert.anchor import (
    compute_anchor_hash,
    build_op_return_payload,
    build_op_return_script,
    derive_bitcoin_address,
    anchor,
    save_receipt,
    load_receipt,
    _hash160,
    _base58check_encode,
    _varint,
    _build_raw_tx,
    _p2pkh_script,
)
from agentcert.types import AnchorReceipt, CertType
from agentcert.exceptions import AnchorError


@pytest.fixture
def creator():
    return generate_keys()


@pytest.fixture
def agent():
    return generate_keys()


@pytest.fixture
def cert(creator, agent):
    return create_certificate(
        creator_keys=creator, agent_keys=agent,
        name="anchor-test", platform="pytest", model_hash="sha256:anchor",
        capabilities=["test"], constraints=["none"],
        risk_tier=1, expires_days=30,
    )


class TestComputeAnchorHash:
    def test_returns_32_bytes(self, cert):
        h = compute_anchor_hash(cert)
        assert isinstance(h, bytes)
        assert len(h) == 32

    def test_deterministic(self, cert):
        h1 = compute_anchor_hash(cert)
        h2 = compute_anchor_hash(cert)
        assert h1 == h2

    def test_different_certs_different_hashes(self, creator, agent):
        c1 = create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="a", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1, timestamp=1000,
        )
        c2 = create_certificate(
            creator_keys=creator, agent_keys=agent,
            name="b", platform="t", model_hash="", capabilities=[], constraints=[],
            risk_tier=1, expires_days=1, timestamp=1000,
        )
        assert compute_anchor_hash(c1) != compute_anchor_hash(c2)


class TestBuildOpReturnPayload:
    def test_length_38(self, cert):
        payload = build_op_return_payload(cert)
        assert len(payload) == 38

    def test_magic_bytes(self, cert):
        payload = build_op_return_payload(cert)
        assert payload[:4] == b"AIT\x00"

    def test_version(self, cert):
        payload = build_op_return_payload(cert)
        assert payload[4] == 0x01

    def test_type_identity_cert(self, cert):
        payload = build_op_return_payload(cert)
        assert payload[5] == 0x02

    def test_type_revocation(self, cert, creator):
        rev = revoke_certificate(previous_cert=cert, creator_keys=creator, reason="done")
        payload = build_op_return_payload(rev)
        assert payload[5] == 0x03

    def test_hash_matches(self, cert):
        payload = build_op_return_payload(cert)
        expected_hash = compute_anchor_hash(cert)
        assert payload[6:] == expected_hash


class TestBuildOpReturnScript:
    def test_op_return_opcode(self, cert):
        payload = build_op_return_payload(cert)
        script = build_op_return_script(payload)
        assert script[0] == 0x6A  # OP_RETURN

    def test_push_length(self, cert):
        payload = build_op_return_payload(cert)
        script = build_op_return_script(payload)
        assert script[1] == 38

    def test_payload_embedded(self, cert):
        payload = build_op_return_payload(cert)
        script = build_op_return_script(payload)
        assert script[2:] == payload

    def test_too_large_payload(self):
        with pytest.raises(AnchorError, match="too large"):
            build_op_return_script(b"\x00" * 81)


class TestDeriveBitcoinAddress:
    def test_testnet_prefix(self, creator):
        addr = derive_bitcoin_address(creator, network="testnet")
        assert addr[0] in ("m", "n")

    def test_mainnet_prefix(self, creator):
        addr = derive_bitcoin_address(creator, network="mainnet")
        assert addr[0] == "1"

    def test_deterministic(self, creator):
        a1 = derive_bitcoin_address(creator, network="testnet")
        a2 = derive_bitcoin_address(creator, network="testnet")
        assert a1 == a2

    def test_different_keys_different_addresses(self):
        k1 = generate_keys()
        k2 = generate_keys()
        assert derive_bitcoin_address(k1) != derive_bitcoin_address(k2)

    def test_invalid_network(self, creator):
        with pytest.raises(AnchorError, match="Unknown network"):
            derive_bitcoin_address(creator, network="regtest")


class TestBitcoinHelpers:
    def test_hash160_length(self):
        result = _hash160(b"test data")
        assert len(result) == 20

    def test_varint_small(self):
        assert _varint(0) == b"\x00"
        assert _varint(252) == b"\xfc"

    def test_varint_medium(self):
        assert _varint(253) == b"\xfd\xfd\x00"
        assert _varint(65535) == b"\xfd\xff\xff"

    def test_p2pkh_script_length(self):
        script = _p2pkh_script(b"\x00" * 20)
        assert len(script) == 25
        assert script[0] == 0x76  # OP_DUP
        assert script[1] == 0xA9  # OP_HASH160
        assert script[2] == 0x14  # push 20 bytes
        assert script[-2] == 0x88  # OP_EQUALVERIFY
        assert script[-1] == 0xAC  # OP_CHECKSIG


class TestTransactionBuilding:
    def test_tx_version(self, creator, cert):
        payload = build_op_return_payload(cert)
        or_script = build_op_return_script(payload)
        pubkey_hash = _hash160(bytes.fromhex(creator.public_key_hex))
        change_script = _p2pkh_script(pubkey_hash)

        tx = _build_raw_tx(
            utxo_txid_hex="aa" * 32,
            utxo_vout=0,
            input_script=_p2pkh_script(pubkey_hash),
            op_return_script=or_script,
            change_script=change_script,
            change_value_sats=9000,
        )
        assert tx[:4] == b"\x02\x00\x00\x00"  # version 2

    def test_tx_locktime(self, creator, cert):
        payload = build_op_return_payload(cert)
        or_script = build_op_return_script(payload)
        pubkey_hash = _hash160(bytes.fromhex(creator.public_key_hex))
        change_script = _p2pkh_script(pubkey_hash)

        tx = _build_raw_tx(
            utxo_txid_hex="aa" * 32,
            utxo_vout=0,
            input_script=b"",
            op_return_script=or_script,
            change_script=change_script,
            change_value_sats=9000,
        )
        assert tx[-4:] == b"\x00\x00\x00\x00"  # locktime 0


class TestReceiptSaveLoad:
    def test_roundtrip(self, tmp_path):
        receipt = AnchorReceipt(
            txid="abc123",
            network="testnet",
            anchor_hash="ff" * 32,
            op_return_hex="ee" * 38,
            cert_id="dd" * 32,
        )
        path = tmp_path / "receipt.json"
        save_receipt(receipt, path)
        loaded = load_receipt(path)
        assert loaded == receipt

    def test_file_is_valid_json(self, tmp_path):
        receipt = AnchorReceipt(
            txid="abc", network="testnet",
            anchor_hash="ff" * 32, op_return_hex="ee" * 38, cert_id="dd" * 32,
        )
        path = tmp_path / "receipt.json"
        save_receipt(receipt, path)
        data = json.loads(path.read_text())
        assert data["txid"] == "abc"
        assert data["network"] == "testnet"


class TestAnchorIntegration:
    @responses.activate
    def test_anchor_no_utxos(self, creator, cert):
        address = derive_bitcoin_address(creator, network="testnet")
        responses.add(
            responses.GET,
            f"https://blockstream.info/testnet/api/address/{address}/utxo",
            json=[],
            status=200,
        )
        with pytest.raises(AnchorError, match="No UTXOs"):
            anchor(cert, creator_keys=creator, network="testnet")

    @responses.activate
    def test_anchor_insufficient_balance(self, creator, cert):
        address = derive_bitcoin_address(creator, network="testnet")
        responses.add(
            responses.GET,
            f"https://blockstream.info/testnet/api/address/{address}/utxo",
            json=[{"txid": "aa" * 32, "vout": 0, "value": 100, "status": {"confirmed": True}}],
            status=200,
        )
        with pytest.raises(AnchorError, match="sufficient balance"):
            anchor(cert, creator_keys=creator, network="testnet")

    @responses.activate
    def test_anchor_success(self, creator, cert):
        address = derive_bitcoin_address(creator, network="testnet")
        fake_txid = "bb" * 32

        responses.add(
            responses.GET,
            f"https://blockstream.info/testnet/api/address/{address}/utxo",
            json=[{"txid": "aa" * 32, "vout": 0, "value": 50000, "status": {"confirmed": True}}],
            status=200,
        )
        responses.add(
            responses.POST,
            "https://blockstream.info/testnet/api/tx",
            body=fake_txid,
            status=200,
        )

        receipt = anchor(cert, creator_keys=creator, network="testnet")
        assert receipt.txid == fake_txid
        assert receipt.network == "testnet"
        assert receipt.cert_id == cert.cert_id
        assert receipt.anchor_hash == compute_anchor_hash(cert).hex()

    @responses.activate
    def test_anchor_api_failure(self, creator, cert):
        address = derive_bitcoin_address(creator, network="testnet")
        responses.add(
            responses.GET,
            f"https://blockstream.info/testnet/api/address/{address}/utxo",
            body="Server Error",
            status=500,
        )
        with pytest.raises(AnchorError, match="Failed to fetch"):
            anchor(cert, creator_keys=creator, network="testnet")
