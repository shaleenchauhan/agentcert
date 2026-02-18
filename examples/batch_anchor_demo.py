"""AgentCert Merkle Batch Anchoring Demo.

Demonstrates Merkle tree batching of audit entries:

    1. Create certificate and audit trail
    2. Log 10 actions
    3. Batch all entries into a Merkle tree
    4. Generate proofs for each entry
    5. Verify individual entries against the batch
    6. Save and reload batch + proofs
    7. Re-verify from loaded files

No real Bitcoin anchoring — this demo runs entirely offline.

Run:
    python examples/batch_anchor_demo.py
"""

import shutil
import tempfile

import agentcert


def section(title: str) -> None:
    print(f"\n{'=' * 64}")
    print(f"  {title}")
    print(f"{'=' * 64}\n")


def main() -> None:
    # ── Step 1: Setup ────────────────────────────────────────────────────

    section("Step 1: Create Certificate + Trail")

    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="batch-demo-agent",
        platform="test",
        model_hash="sha256:demo",
        capabilities=["search", "compute"],
        constraints=["read-only"],
        risk_tier=2,
        expires_days=90,
    )
    print(f"Certificate: {cert.cert_id[:32]}...")

    trail = agentcert.create_audit_trail(cert, agent_keys)
    print(f"Trail:       {trail.trail_id[:32]}...")

    # ── Step 2: Log Actions ──────────────────────────────────────────────

    section("Step 2: Log 10 Actions")

    actions = [
        (agentcert.ActionType.API_CALL, "Called weather API"),
        (agentcert.ActionType.TOOL_USE, "Ran web_search tool"),
        (agentcert.ActionType.DECISION, "Selected vendor A"),
        (agentcert.ActionType.API_CALL, "Called pricing API"),
        (agentcert.ActionType.TOOL_USE, "Ran calculator tool"),
        (agentcert.ActionType.DATA_ACCESS, "Read inventory database"),
        (agentcert.ActionType.DECISION, "Chose shipping method"),
        (agentcert.ActionType.TRANSACTION, "Placed purchase order"),
        (agentcert.ActionType.COMMUNICATION, "Sent email confirmation"),
        (agentcert.ActionType.API_CALL, "Called tracking API"),
    ]

    for action_type, summary in actions:
        entry = agentcert.log_action(
            trail, agent_keys,
            action_type=action_type,
            action_summary=summary,
        )
        print(f"  [seq {entry.sequence}] {agentcert.ActionType(entry.action_type).name:15s} | {summary}")

    print(f"\nTotal entries: {len(trail.entries)}")

    # ── Step 3: Batch into Merkle Tree ───────────────────────────────────

    section("Step 3: Batch into Merkle Tree")

    batch, tree = agentcert.create_batch_from_trail(trail)

    print(f"Batch ID:     {batch.batch_id[:32]}...")
    print(f"Merkle root:  {batch.merkle_root[:32]}...")
    print(f"Items:        {batch.item_count}")
    print(f"Anchored:     {'yes' if batch.anchor_receipt else 'no'}")

    # Show the cost savings
    print(f"\nWithout batching: {batch.item_count} Bitcoin transactions")
    print(f"With batching:    1 Bitcoin transaction")

    # ── Step 4: Generate Proofs ──────────────────────────────────────────

    section("Step 4: Generate Merkle Proofs")

    proofs = {}
    for entry in trail.entries:
        proof = agentcert.get_proof_for_entry(entry, tree, batch)
        proofs[entry.entry_id] = proof
        print(f"  Entry {entry.sequence}: {len(proof.siblings)} siblings "
              f"(leaf {proof.leaf_index})")

    print(f"\nProof size for {batch.item_count} entries: "
          f"{len(proofs[trail.entries[0].entry_id].siblings)} hashes "
          f"(O(log n) = log2({batch.item_count}))")

    # ── Step 5: Verify Entries ───────────────────────────────────────────

    section("Step 5: Verify Each Entry")

    all_valid = True
    for entry in trail.entries:
        result = agentcert.verify_entry_in_batch(
            entry, proofs[entry.entry_id], batch, certificate=cert,
        )
        status_str = f"[{result.status}]"
        print(f"  Entry {entry.sequence}: {status_str:16s} "
              f"proof={'OK' if result.proof_valid else 'FAIL'} "
              f"anchor={'N/A' if result.anchor_valid is None else 'OK'}")
        if not result.valid:
            all_valid = False

    print(f"\nAll entries valid: {all_valid}")

    # Show checks for one entry in detail
    print(f"\nDetailed checks for entry 5:")
    result = agentcert.verify_entry_in_batch(
        trail.entries[5], proofs[trail.entries[5].entry_id], batch, certificate=cert,
    )
    for check in result.checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  [{status}] {check.name}: {check.detail}")

    # ── Step 6: Save and Reload ──────────────────────────────────────────

    section("Step 6: Save & Reload")

    save_dir = tempfile.mkdtemp(prefix="agentcert_batch_")
    agentcert.save_batch(batch, f"{save_dir}/batch.json")
    agentcert.save_proofs(proofs, f"{save_dir}/proofs.json")
    agentcert.save_trail(trail, f"{save_dir}/trail.json")
    agentcert.save_certificate(cert, f"{save_dir}/cert.json")

    print(f"Saved to: {save_dir}/")
    print(f"  batch.json   — batch metadata + merkle root")
    print(f"  proofs.json  — Merkle proofs for all entries")
    print(f"  trail.json   — audit trail")
    print(f"  cert.json    — certificate")

    # Reload
    loaded_batch = agentcert.load_batch(f"{save_dir}/batch.json")
    loaded_proofs = agentcert.load_proofs(f"{save_dir}/proofs.json")
    print(f"\nReloaded: {loaded_batch.item_count} items, {len(loaded_proofs)} proofs")

    # ── Step 7: Re-verify from Loaded Files ──────────────────────────────

    section("Step 7: Re-verify from Loaded Files")

    for entry in trail.entries:
        result = agentcert.verify_batch_proof(
            entry.entry_id, loaded_proofs[entry.entry_id], loaded_batch,
        )
        assert result.valid, f"Entry {entry.sequence} failed re-verification"

    print(f"Re-verified all {len(trail.entries)} entries from loaded files.")

    # Cleanup
    shutil.rmtree(save_dir)

    # ── Production Usage ─────────────────────────────────────────────────

    section("Production Usage")

    print("""In production, you'd anchor the batch to Bitcoin:

    # After creating the batch:
    batch = agentcert.anchor_batch(
        batch,
        creator_keys=creator_keys,
        network="testnet",
    )
    print(f"Anchored: {batch.anchor_receipt.txid}")

    # Then verification shows "VALID" instead of "NOT_ANCHORED":
    result = agentcert.verify_entry_in_batch(entry, proof, batch, cert)
    print(result.status)  # "VALID"

    # One Bitcoin transaction proves ALL entries in the batch.
""")

    print("Done. Merkle batch anchoring demo complete.")


if __name__ == "__main__":
    main()
