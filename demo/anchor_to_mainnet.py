"""Batch all 5 agent audit trails into a Merkle tree and anchor to Bitcoin mainnet."""

import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

import agentcert

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

AGENT_DIRS = [
    "security-monitor",
    "ecosystem-tracker",
    "code-reviewer",
    "shopping-agent",
    "vendor-agent",
]


def load_all_trails():
    """Load all audit trails from agent output directories."""
    trails = {}
    for agent_dir in AGENT_DIRS:
        trail_path = os.path.join(OUTPUT_DIR, agent_dir, "trail.json")
        if not os.path.exists(trail_path):
            print(f"  ⚠ Skipping {agent_dir} — trail.json not found")
            continue
        trail = agentcert.load_trail(trail_path)
        trails[agent_dir] = trail
        print(f"  ✓ {agent_dir}: {len(trail.entries)} entries (cert: {trail.cert_id[:16]}...)")
    return trails


def main():
    print("═" * 60)
    print("  AGENTCERT — BITCOIN MAINNET ANCHORING")
    print("═" * 60)

    # 1. Load creator keys
    creator_keys = agentcert.load_keys(os.path.join(KEYS_DIR, "creator.keys.json"))
    address = agentcert.derive_bitcoin_address(creator_keys, network="mainnet")
    print(f"\nCreator Bitcoin address: {address}\n")

    # 2. Load all trails
    print("Phase 1: Loading Audit Trails")
    print("─" * 40)
    trails = load_all_trails()

    total_entries = sum(len(t.entries) for t in trails.values())
    print(f"\n  Agents loaded: {len(trails)}")
    print(f"  Total entries: {total_entries}\n")

    if not trails:
        print("No trails found. Run the agents first.")
        return

    # 3. Collect all entries and create batch
    print("Phase 2: Creating Merkle Batch")
    print("─" * 40)

    all_entries = []
    for trail in trails.values():
        all_entries.extend(trail.entries)

    batch, tree = agentcert.create_batch_from_entries(all_entries)
    print(f"  ✓ Batch created")
    print(f"    Batch ID:    {batch.batch_id[:16]}...")
    print(f"    Merkle root: {batch.merkle_root[:16]}...")
    print(f"    Items:       {batch.item_count}\n")

    # 4. Anchor to Bitcoin mainnet
    print("Phase 3: Anchoring to Bitcoin Mainnet")
    print("─" * 40)
    print(f"  Broadcasting OP_RETURN transaction...")
    print(f"  Merkle root: {batch.merkle_root}")

    anchored_batch = agentcert.anchor_batch(
        batch,
        creator_keys=creator_keys,
        network="mainnet",
        fee_sats=1000,
    )

    receipt = anchored_batch.anchor_receipt
    print(f"\n  ✓ ANCHORED TO BITCOIN MAINNET")
    print(f"    Transaction ID: {receipt.txid}")
    print(f"    Network:        {receipt.network}")
    print(f"    OP_RETURN:      {receipt.op_return_hex[:40]}...\n")

    # 5. Generate and save proofs
    print("Phase 4: Generating Merkle Proofs")
    print("─" * 40)

    all_proofs = {}
    for agent_name, trail in trails.items():
        count = 0
        for entry in trail.entries:
            proof = agentcert.get_proof_for_entry(entry, tree, batch)
            all_proofs[entry.entry_id] = proof
            count += 1
        print(f"  ✓ {agent_name}: {count} proofs")

    proofs_path = os.path.join(OUTPUT_DIR, "mainnet-proofs.json")
    agentcert.save_proofs(all_proofs, proofs_path)
    print(f"\n  All proofs saved to: {proofs_path}")

    # 6. Save batch
    batch_path = os.path.join(OUTPUT_DIR, "mainnet-batch.json")
    agentcert.save_batch(anchored_batch, batch_path)
    print(f"  Batch saved to: {batch_path}\n")

    # 7. Save summary metadata
    summary = {
        "merkle_root": anchored_batch.merkle_root,
        "txid": receipt.txid,
        "network": "mainnet",
        "total_entries": total_entries,
        "agents": {
            name: {
                "entries": len(trail.entries),
                "cert_id": trail.cert_id,
            }
            for name, trail in trails.items()
        },
        "blockchain_url": f"https://mempool.space/tx/{receipt.txid}",
    }

    summary_path = os.path.join(OUTPUT_DIR, "mainnet-anchor.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # 8. Print summary
    print("Phase 5: Summary")
    print("─" * 40)
    print(f"  Agents anchored:    {len(trails)}")
    print(f"  Total audit entries: {total_entries}")
    print(f"  Merkle root:        {anchored_batch.merkle_root}")
    print(f"  Bitcoin txid:       {receipt.txid}")
    print()
    print(f"  View on blockchain:")
    print(f"  https://mempool.space/tx/{receipt.txid}")
    print()
    print("═" * 60)
    print("  ALL 5 AGENTS ANCHORED TO BITCOIN MAINNET ✓")
    print("═" * 60)


if __name__ == "__main__":
    main()
