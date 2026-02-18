"""Bitcoin anchoring via OP_RETURN and the Blockstream API."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes

from agentcert.exceptions import AnchorError
from agentcert.types import AnchorReceipt, Certificate, CertType, KeyPair


# ── Protocol constants ───────────────────────────────────────────────────────

AIT_MAGIC = b"AIT\x00"
AIT_VERSION = b"\x01"

PAYLOAD_TYPES: dict[int, bytes] = {
    CertType.CREATION: b"\x02",    # IDENTITY_CERT
    CertType.UPDATE: b"\x02",      # IDENTITY_CERT
    CertType.REVOCATION: b"\x03",  # REVOCATION
}

# ── Bitcoin constants ────────────────────────────────────────────────────────

_SIGHASH_ALL = 0x01
_TX_VERSION = 2
_DEFAULT_FEE_SATS = 1000  # safe minimum for testnet
_SEQUENCE = 0xFFFFFFFF

_P2PKH_VERSIONS = {"mainnet": 0x00, "testnet": 0x6F}

_BECH32_HRPS = {"mainnet": "bc", "testnet": "tb"}

_API_BASES = {
    "mainnet": "https://blockstream.info/api",
    "testnet": "https://blockstream.info/testnet/api",
}

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# ═══════════════════════════════════════════════════════════════════════════════
# Pure functions (no network I/O)
# ═══════════════════════════════════════════════════════════════════════════════


def compute_anchor_hash(cert: Certificate) -> bytes:
    """Compute the SHA-256 hash of the complete canonical certificate.

    This is the 32-byte value that gets embedded in the OP_RETURN payload.

    Args:
        cert: The certificate to hash.

    Returns:
        32-byte SHA-256 digest.
    """
    return hashlib.sha256(cert.canonical_bytes()).digest()


def build_op_return_payload(cert: Certificate) -> bytes:
    """Build the 38-byte AIT OP_RETURN payload.

    Format: AIT\\x00 (4) + version (1) + type (1) + SHA-256 hash (32) = 38 bytes.

    Args:
        cert: The certificate to anchor.

    Returns:
        38-byte payload.

    Raises:
        AnchorError: If the cert_type has no defined payload type.
    """
    payload_type = PAYLOAD_TYPES.get(cert.cert_type)
    if payload_type is None:
        raise AnchorError(f"No OP_RETURN payload type for cert_type={cert.cert_type}")

    anchor_hash = compute_anchor_hash(cert)
    payload = AIT_MAGIC + AIT_VERSION + payload_type + anchor_hash

    assert len(payload) == 38, f"Payload must be 38 bytes, got {len(payload)}"
    return payload


def build_op_return_script(payload: bytes) -> bytes:
    """Wrap a payload in an OP_RETURN script.

    Args:
        payload: The data to embed (must be <= 80 bytes).

    Returns:
        The complete script bytes (OP_RETURN + push + payload).

    Raises:
        AnchorError: If payload exceeds 80 bytes.
    """
    if len(payload) > 80:
        raise AnchorError(f"OP_RETURN payload too large: {len(payload)} bytes (max 80)")

    if len(payload) <= 75:
        return b"\x6a" + bytes([len(payload)]) + payload
    else:
        return b"\x6a\x4c" + bytes([len(payload)]) + payload


def derive_bitcoin_address(keys: KeyPair, *, network: str = "testnet") -> str:
    """Derive a P2PKH Bitcoin address from a key pair.

    Args:
        keys: The key pair (uses the compressed public key).
        network: "testnet" or "mainnet".

    Returns:
        A Base58Check-encoded P2PKH address.

    Raises:
        AnchorError: If the network is invalid.
    """
    if network not in _P2PKH_VERSIONS:
        raise AnchorError(f"Unknown network: {network!r} (use 'testnet' or 'mainnet')")

    pubkey_bytes = bytes.fromhex(keys.public_key_hex)
    h160 = _hash160(pubkey_bytes)
    return _base58check_encode(_P2PKH_VERSIONS[network], h160)


def derive_segwit_address(keys: KeyPair, *, network: str = "testnet") -> str:
    """Derive a native SegWit (P2WPKH / bech32) address from a key pair.

    Args:
        keys: The key pair (uses the compressed public key).
        network: "testnet" or "mainnet".

    Returns:
        A bech32-encoded P2WPKH address (bc1... or tb1...).

    Raises:
        AnchorError: If the network is invalid.
    """
    hrp = _BECH32_HRPS.get(network)
    if hrp is None:
        raise AnchorError(f"Unknown network: {network!r} (use 'testnet' or 'mainnet')")

    pubkey_bytes = bytes.fromhex(keys.public_key_hex)
    h160 = _hash160(pubkey_bytes)
    return _bech32_encode(hrp, 0, h160)


# ═══════════════════════════════════════════════════════════════════════════════
# Bitcoin transaction helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — standard Bitcoin Hash160."""
    sha = hashlib.sha256(data).digest()
    try:
        ripemd = hashlib.new("ripemd160", sha, usedforsecurity=False)
    except TypeError:
        ripemd = hashlib.new("ripemd160", sha)
    return ripemd.digest()


def _base58check_encode(version: int, payload: bytes) -> str:
    """Base58Check encode with a version byte."""
    data = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + checksum

    # Convert to integer and encode in base58
    n = int.from_bytes(full, "big")
    result: list[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_BASE58_ALPHABET[r])

    # Preserve leading zero bytes as '1's
    for byte in full:
        if byte == 0:
            result.append(_BASE58_ALPHABET[0])
        else:
            break

    return "".join(reversed(result))


def _bech32_polymod(values: list[int]) -> int:
    """Internal bech32 checksum computation."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP for bech32 checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    """Compute the bech32 checksum."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """Convert between bit groupings (e.g. 8-bit bytes to 5-bit groups for bech32)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return []
    return ret


def _bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a witness program as a bech32 address.

    Args:
        hrp: Human-readable part ("bc" for mainnet, "tb" for testnet).
        witver: Witness version (0 for P2WPKH).
        witprog: Witness program (20 bytes for P2WPKH).

    Returns:
        The bech32-encoded address string.
    """
    data = [witver] + _convertbits(witprog, 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def _p2wpkh_script(pubkey_hash: bytes) -> bytes:
    """Build a P2WPKH scriptPubKey: OP_0 <20-byte-hash>."""
    return b"\x00\x14" + pubkey_hash


def _varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin varint."""
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def _push_data(data: bytes) -> bytes:
    """Create a script push-data operation for the given bytes."""
    length = len(data)
    if length < 0x4C:
        return bytes([length]) + data
    elif length <= 0xFF:
        return b"\x4c" + bytes([length]) + data
    elif length <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", length) + data
    else:
        return b"\x4e" + struct.pack("<I", length) + data


def _p2pkh_script(pubkey_hash: bytes) -> bytes:
    """Build a P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG."""
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"


def _build_raw_tx(
    utxo_txid_hex: str,
    utxo_vout: int,
    input_script: bytes,
    op_return_script: bytes,
    change_script: bytes,
    change_value_sats: int,
    *,
    append_sighash: bool = False,
) -> bytes:
    """Build a raw Bitcoin transaction with an OP_RETURN and change output.

    Args:
        utxo_txid_hex: The UTXO txid as a hex string (natural byte order).
        utxo_vout: The UTXO output index.
        input_script: The scriptSig (or scriptPubKey for signing).
        op_return_script: The complete OP_RETURN script.
        change_script: The P2PKH change output script.
        change_value_sats: The change amount in satoshis.
        append_sighash: If True, append SIGHASH_ALL for signing.

    Returns:
        The raw transaction bytes.
    """
    tx = b""

    # Version
    tx += struct.pack("<I", _TX_VERSION)

    # Inputs
    tx += _varint(1)
    tx += bytes.fromhex(utxo_txid_hex)[::-1]  # txid reversed
    tx += struct.pack("<I", utxo_vout)
    tx += _varint(len(input_script))
    tx += input_script
    tx += struct.pack("<I", _SEQUENCE)

    # Outputs
    tx += _varint(2)

    # Output 0: OP_RETURN (0 sats)
    tx += struct.pack("<Q", 0)
    tx += _varint(len(op_return_script))
    tx += op_return_script

    # Output 1: Change
    tx += struct.pack("<Q", change_value_sats)
    tx += _varint(len(change_script))
    tx += change_script

    # Locktime
    tx += struct.pack("<I", 0)

    if append_sighash:
        tx += struct.pack("<I", _SIGHASH_ALL)

    return tx


def _sign_p2pkh_input(
    private_key: ec.EllipticCurvePrivateKey,
    public_key_hex: str,
    tx_for_signing: bytes,
) -> bytes:
    """Sign a P2PKH input and return the scriptSig.

    Args:
        private_key: The private key to sign with.
        public_key_hex: The compressed public key hex.
        tx_for_signing: The serialized transaction with sighash appended.

    Returns:
        The scriptSig bytes (<sig+hashtype> <pubkey>).
    """
    # Double SHA-256
    sighash = hashlib.sha256(hashlib.sha256(tx_for_signing).digest()).digest()

    # ECDSA sign over the pre-hashed value
    sig_der = private_key.sign(sighash, ec.ECDSA(Prehashed(hashes.SHA256())))
    sig_with_hashtype = sig_der + bytes([_SIGHASH_ALL])

    pubkey_bytes = bytes.fromhex(public_key_hex)
    return _push_data(sig_with_hashtype) + _push_data(pubkey_bytes)


def _build_segwit_tx(
    utxo_txid_hex: str,
    utxo_vout: int,
    utxo_value_sats: int,
    private_key: ec.EllipticCurvePrivateKey,
    public_key_hex: str,
    pubkey_hash: bytes,
    op_return_script: bytes,
    change_value_sats: int,
) -> bytes:
    """Build and sign a SegWit (P2WPKH) transaction with an OP_RETURN output.

    Uses BIP-143 sighash for SegWit input signing.

    Returns:
        The serialized signed SegWit transaction.
    """
    change_script = _p2wpkh_script(pubkey_hash)
    prevout_hash = bytes.fromhex(utxo_txid_hex)[::-1]

    # BIP-143 sighash preimage components
    # hashPrevouts = SHA256(SHA256(outpoint))
    outpoint = prevout_hash + struct.pack("<I", utxo_vout)
    hash_prevouts = hashlib.sha256(hashlib.sha256(outpoint).digest()).digest()

    # hashSequence = SHA256(SHA256(sequence))
    hash_sequence = hashlib.sha256(
        hashlib.sha256(struct.pack("<I", _SEQUENCE)).digest()
    ).digest()

    # hashOutputs = SHA256(SHA256(all outputs serialized))
    outputs = b""
    # Output 0: OP_RETURN
    outputs += struct.pack("<Q", 0)
    outputs += _varint(len(op_return_script))
    outputs += op_return_script
    # Output 1: Change
    outputs += struct.pack("<Q", change_value_sats)
    outputs += _varint(len(change_script))
    outputs += change_script
    hash_outputs = hashlib.sha256(hashlib.sha256(outputs).digest()).digest()

    # scriptCode for P2WPKH = OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    script_code = _p2pkh_script(pubkey_hash)

    # BIP-143 preimage
    preimage = b""
    preimage += struct.pack("<I", _TX_VERSION)       # nVersion
    preimage += hash_prevouts                         # hashPrevouts
    preimage += hash_sequence                         # hashSequence
    preimage += outpoint                              # outpoint
    preimage += _varint(len(script_code)) + script_code  # scriptCode
    preimage += struct.pack("<Q", utxo_value_sats)    # value
    preimage += struct.pack("<I", _SEQUENCE)           # nSequence
    preimage += hash_outputs                          # hashOutputs
    preimage += struct.pack("<I", 0)                   # nLocktime
    preimage += struct.pack("<I", _SIGHASH_ALL)        # sighash type

    # Sign
    sighash = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    sig_der = private_key.sign(sighash, ec.ECDSA(Prehashed(hashes.SHA256())))
    sig_with_hashtype = sig_der + bytes([_SIGHASH_ALL])

    # Build the witness
    pubkey_bytes = bytes.fromhex(public_key_hex)

    # Serialize the full SegWit transaction
    tx = b""
    tx += struct.pack("<I", _TX_VERSION)
    tx += b"\x00\x01"  # SegWit marker + flag

    # Input (empty scriptSig for SegWit)
    tx += _varint(1)
    tx += prevout_hash
    tx += struct.pack("<I", utxo_vout)
    tx += _varint(0)  # empty scriptSig
    tx += struct.pack("<I", _SEQUENCE)

    # Outputs
    tx += _varint(2)
    tx += outputs

    # Witness
    tx += b"\x02"  # 2 witness items
    tx += _varint(len(sig_with_hashtype)) + sig_with_hashtype
    tx += _varint(len(pubkey_bytes)) + pubkey_bytes

    # Locktime
    tx += struct.pack("<I", 0)

    return tx


# ═══════════════════════════════════════════════════════════════════════════════
# Network functions (Blockstream API)
# ═══════════════════════════════════════════════════════════════════════════════


def _get_api_base(network: str) -> str:
    """Get the Blockstream API base URL for a network."""
    base = _API_BASES.get(network)
    if base is None:
        raise AnchorError(f"Unknown network: {network!r} (use 'testnet' or 'mainnet')")
    return base


def _fetch_utxos(address: str, network: str) -> list[dict[str, Any]]:
    """Fetch unspent transaction outputs for an address.

    Args:
        address: The Bitcoin address.
        network: "testnet" or "mainnet".

    Returns:
        List of UTXO dicts with keys: txid, vout, value, status.

    Raises:
        AnchorError: If the API request fails.
    """
    base = _get_api_base(network)
    url = f"{base}/address/{address}/utxo"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise AnchorError(f"Failed to fetch UTXOs for {address}: {exc}") from exc


def _broadcast_tx(tx_hex: str, network: str) -> str:
    """Broadcast a raw transaction via the Blockstream API.

    Args:
        tx_hex: The signed transaction as a hex string.
        network: "testnet" or "mainnet".

    Returns:
        The transaction ID.

    Raises:
        AnchorError: If broadcasting fails.
    """
    base = _get_api_base(network)
    url = f"{base}/tx"
    try:
        resp = requests.post(url, data=tx_hex, timeout=30)
        resp.raise_for_status()
        return resp.text.strip()
    except requests.RequestException as exc:
        raise AnchorError(f"Failed to broadcast transaction: {exc}") from exc


def anchor(
    cert: Certificate,
    *,
    creator_keys: KeyPair,
    network: str = "testnet",
    fee_sats: int = _DEFAULT_FEE_SATS,
) -> AnchorReceipt:
    """Anchor a certificate to Bitcoin via an OP_RETURN transaction.

    The creator's key pair is used to fund and sign the Bitcoin transaction.
    The derived Bitcoin address must have a sufficient UTXO balance (>= fee_sats).

    Args:
        cert: The certificate to anchor.
        creator_keys: The creator's key pair (used as the Bitcoin funding key).
        network: "testnet" or "mainnet".
        fee_sats: Transaction fee in satoshis (default: 1000).

    Returns:
        An AnchorReceipt with the txid and anchor details.

    Raises:
        AnchorError: If anchoring fails (no UTXOs, broadcast failure, etc.).
    """
    # Build the OP_RETURN payload and script
    payload = build_op_return_payload(cert)
    or_script = build_op_return_script(payload)

    # Derive SegWit address and try it first, fall back to legacy P2PKH
    pubkey_bytes = bytes.fromhex(creator_keys.public_key_hex)
    pubkey_hash = _hash160(pubkey_bytes)

    segwit_addr = derive_segwit_address(creator_keys, network=network)
    legacy_addr = derive_bitcoin_address(creator_keys, network=network)

    utxos = _fetch_utxos(segwit_addr, network)
    use_segwit = True

    if not utxos:
        utxos = _fetch_utxos(legacy_addr, network)
        use_segwit = False

    address = segwit_addr if use_segwit else legacy_addr

    if not utxos:
        raise AnchorError(
            f"No UTXOs found on {network}. Fund one of these addresses first:\n"
            f"  SegWit:  {segwit_addr}\n"
            f"  Legacy:  {legacy_addr}"
        )

    # Select a UTXO with enough value
    utxo = None
    for u in utxos:
        if u["value"] >= fee_sats:
            utxo = u
            break

    if utxo is None:
        raise AnchorError(
            f"No UTXO with sufficient balance (>= {fee_sats} sats) "
            f"found for {address} on {network}."
        )

    utxo_txid = utxo["txid"]
    utxo_vout = utxo["vout"]
    utxo_value = utxo["value"]
    change_value = utxo_value - fee_sats

    if use_segwit:
        signed_tx = _build_segwit_tx(
            utxo_txid_hex=utxo_txid,
            utxo_vout=utxo_vout,
            utxo_value_sats=utxo_value,
            private_key=creator_keys.private_key,
            public_key_hex=creator_keys.public_key_hex,
            pubkey_hash=pubkey_hash,
            op_return_script=or_script,
            change_value_sats=change_value,
        )
    else:
        # Legacy P2PKH path
        utxo_script_pubkey = _p2pkh_script(pubkey_hash)
        change_script = _p2pkh_script(pubkey_hash)

        tx_for_signing = _build_raw_tx(
            utxo_txid_hex=utxo_txid,
            utxo_vout=utxo_vout,
            input_script=utxo_script_pubkey,
            op_return_script=or_script,
            change_script=change_script,
            change_value_sats=change_value,
            append_sighash=True,
        )

        script_sig = _sign_p2pkh_input(
            creator_keys.private_key,
            creator_keys.public_key_hex,
            tx_for_signing,
        )

        signed_tx = _build_raw_tx(
            utxo_txid_hex=utxo_txid,
            utxo_vout=utxo_vout,
            input_script=script_sig,
            op_return_script=or_script,
            change_script=change_script,
            change_value_sats=change_value,
            append_sighash=False,
        )

    # Broadcast
    txid = _broadcast_tx(signed_tx.hex(), network)

    return AnchorReceipt(
        txid=txid,
        network=network,
        anchor_hash=compute_anchor_hash(cert).hex(),
        op_return_hex=payload.hex(),
        cert_id=cert.cert_id,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Receipt save/load
# ═══════════════════════════════════════════════════════════════════════════════


def save_receipt(receipt: AnchorReceipt, path: str | Path) -> None:
    """Save an anchor receipt to a JSON file.

    Args:
        receipt: The receipt to save.
        path: File path to write to.

    Raises:
        AnchorError: If saving fails.
    """
    try:
        Path(path).write_text(
            json.dumps(receipt.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        raise AnchorError(f"Failed to save receipt to {path}: {exc}") from exc


def load_receipt(path: str | Path) -> AnchorReceipt:
    """Load an anchor receipt from a JSON file.

    Args:
        path: File path to read from.

    Returns:
        The loaded AnchorReceipt.

    Raises:
        AnchorError: If loading or parsing fails.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return AnchorReceipt.from_dict(data)
    except Exception as exc:
        raise AnchorError(f"Failed to load receipt from {path}: {exc}") from exc
