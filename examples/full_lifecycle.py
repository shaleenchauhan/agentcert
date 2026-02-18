"""AgentCert Full Lifecycle — create, update, revoke, and verify a certificate chain.

Demonstrates the complete lifecycle of an AI agent identity certificate:
    1. Key generation
    2. Certificate creation
    3. Verification (all 6 checks)
    4. Certificate update (add capabilities)
    5. Certificate revocation
    6. Chain verification

Run:
    python examples/full_lifecycle.py
"""

import agentcert


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def print_checks(checks: tuple[agentcert.VerificationCheck, ...]) -> None:
    for check in checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  [{status}] {check.name}: {check.detail}")


def main() -> None:
    # ── Step 1: Key Generation ───────────────────────────────────────────

    section("Step 1: Key Generation")

    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    print(f"Creator:")
    print(f"  Public key: {creator_keys.public_key_hex}")
    print(f"  Identity:   {creator_keys.identity}")
    print(f"Agent:")
    print(f"  Public key: {agent_keys.public_key_hex}")
    print(f"  Identity:   {agent_keys.identity}")

    # Derive Bitcoin address (for future anchoring)
    btc_address = agentcert.derive_bitcoin_address(creator_keys, network="testnet")
    print(f"\nBitcoin testnet address: {btc_address}")
    print(f"  (Fund this address to anchor certificates)")

    # ── Step 2: Certificate Creation ─────────────────────────────────────

    section("Step 2: Certificate Creation")

    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="procurement-agent-v1",
        platform="langchain",
        model_hash="sha256:a1b2c3d4e5f67890abcdef1234567890",
        capabilities=["procurement", "negotiation"],
        constraints=["max-transaction-50000-usd", "requires-human-approval"],
        risk_tier=3,
        expires_days=90,
    )

    print(f"Certificate created:")
    print(f"  cert_id:      {cert.cert_id}")
    print(f"  cert_type:    CREATION ({cert.cert_type})")
    print(f"  agent:        {cert.agent_metadata.name}")
    print(f"  capabilities: {', '.join(cert.agent_metadata.capabilities)}")
    print(f"  constraints:  {', '.join(cert.agent_metadata.constraints)}")
    print(f"  risk_tier:    {cert.agent_metadata.risk_tier}")

    # ── Step 3: Verification ─────────────────────────────────────────────

    section("Step 3: Verification (without anchor)")

    result = agentcert.verify(cert)
    print_checks(result.checks)
    print(f"\nStatus: {result.status}")

    # Demonstrate anchor hash computation
    anchor_hash = agentcert.compute_anchor_hash(cert)
    payload = agentcert.build_op_return_payload(cert)
    print(f"\nAnchor hash:      {anchor_hash.hex()}")
    print(f"OP_RETURN payload: {payload.hex()}")
    print(f"  Magic: AIT\\x00  Version: {payload[4]}  Type: {payload[5]} (IDENTITY_CERT)")

    # Verify with a mock anchor receipt
    receipt = agentcert.AnchorReceipt(
        txid="6b3b8cd6624d833e98add57823a7a8ba72134a9de4aae6b7eb7617ebd7cb771c",
        network="testnet",
        anchor_hash=anchor_hash.hex(),
        op_return_hex=payload.hex(),
        cert_id=cert.cert_id,
    )
    result_anchored = agentcert.verify(cert, receipt)
    print(f"\nVerification with anchor receipt: {result_anchored.status}")
    anchor_check = [c for c in result_anchored.checks if c.name == "anchor_integrity"][0]
    print(f"  [{('PASS' if anchor_check.passed else 'FAIL')}] {anchor_check.detail}")

    # ── Step 4: Certificate Update ───────────────────────────────────────

    section("Step 4: Certificate Update")

    updated = agentcert.update_certificate(
        previous_cert=cert,
        creator_keys=creator_keys,
        capabilities=["procurement", "negotiation", "invoicing"],
        constraints=["max-transaction-50000-usd"],
    )

    print(f"Updated certificate:")
    print(f"  cert_id:       {updated.cert_id}")
    print(f"  cert_type:     UPDATE ({updated.cert_type})")
    print(f"  previous_cert: {updated.previous_cert_id}")
    print(f"  capabilities:  {', '.join(updated.agent_metadata.capabilities)}")
    print(f"  constraints:   {', '.join(updated.agent_metadata.constraints)}")
    print(f"\n  Chain linkage: previous_cert_id == original cert_id? "
          f"{'YES' if updated.previous_cert_id == cert.cert_id else 'NO'}")

    # Verify the update independently
    update_result = agentcert.verify(updated)
    print(f"  Verification:  {update_result.status}")

    # ── Step 5: Certificate Revocation ───────────────────────────────────

    section("Step 5: Certificate Revocation")

    revocation = agentcert.revoke_certificate(
        previous_cert=updated,
        creator_keys=creator_keys,
        reason="Agent decommissioned — replaced by procurement-agent-v2",
    )

    print(f"Revocation certificate:")
    print(f"  cert_id:       {revocation.cert_id}")
    print(f"  cert_type:     REVOCATION ({revocation.cert_type})")
    print(f"  previous_cert: {revocation.previous_cert_id}")
    print(f"  reason:        {revocation.revocation_reason}")

    # Revocation OP_RETURN uses type 0x03
    rev_payload = agentcert.build_op_return_payload(revocation)
    print(f"\n  OP_RETURN type: 0x{rev_payload[5]:02x} (REVOCATION)")

    # ── Step 6: Chain Verification ───────────────────────────────────────

    section("Step 6: Chain Verification")

    chain = [cert, updated, revocation]
    chain_result = agentcert.verify_chain(chain)

    print(f"Chain ({chain_result.chain_length} certificates):")
    print_checks(chain_result.checks)
    print(f"\nChain status: {chain_result.status}")

    # ── Save Everything ──────────────────────────────────────────────────

    section("Saving Artifacts")

    agentcert.save_keys(creator_keys, "lifecycle-creator.keys.json")
    agentcert.save_keys(agent_keys, "lifecycle-agent.keys.json")
    agentcert.save_certificate(cert, "lifecycle-v1.cert.json")
    agentcert.save_certificate(updated, "lifecycle-v2.cert.json")
    agentcert.save_certificate(revocation, "lifecycle-revoke.cert.json")

    print("Saved:")
    print("  lifecycle-creator.keys.json")
    print("  lifecycle-agent.keys.json")
    print("  lifecycle-v1.cert.json")
    print("  lifecycle-v2.cert.json")
    print("  lifecycle-revoke.cert.json")

    print(f"\nDone. Full lifecycle complete.")


if __name__ == "__main__":
    main()
