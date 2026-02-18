#!/usr/bin/env python3
"""Demo: AgentCert anchoring service full flow.

Shows the complete developer experience:
1. Start the service (in-process for demo)
2. Create identity locally
3. Register certificate with service
4. Log actions and submit entries
5. Force batch
6. Retrieve proofs
7. Verify via service

Usage:
    python examples/service_demo.py
"""

import threading
import time

import uvicorn

import agentcert
from agentcert.client import AgentCertClient
from agentcert.service.app import create_app
from agentcert.service.config import ServiceConfig
from agentcert.types import ActionType


def main():
    # ── 1. Start service in background ──────────────────────────────────
    config = ServiceConfig(
        db_path="/tmp/agentcert-demo/demo.db",
        batch_interval_seconds=999999,  # disable auto-batching for demo
        batch_min_entries=1,
    )
    app = create_app(config)

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8932, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1)  # wait for server to start

    print("=== AgentCert Service Demo ===\n")

    # ── 2. Create identity locally ──────────────────────────────────────
    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="demo-procurement-agent",
        platform="langchain",
        model_hash="sha256:demo123",
        capabilities=["procurement", "negotiation"],
        constraints=["max-transaction-10000-usd"],
        risk_tier=2,
        expires_days=90,
    )
    print(f"Certificate created: {cert.cert_id[:32]}...")
    print(f"  Agent: {cert.agent_metadata.name}")
    print()

    # ── 3. Connect to service and register ──────────────────────────────
    with AgentCertClient("http://127.0.0.1:8932") as client:
        result = client.register_certificate(cert)
        print(f"Certificate registered: {result['status']}")
        print()

        # ── 4. Log actions locally and submit ───────────────────────────
        trail = agentcert.create_audit_trail(cert=cert, agent_keys=agent_keys)

        actions = [
            (ActionType.API_CALL, "Called weather API for NYC forecast"),
            (ActionType.TOOL_USE, "Ran web_search: supplier pricing"),
            (ActionType.DECISION, "Selected vendor: Acme Corp (lowest bid)"),
            (ActionType.API_CALL, "Called Acme pricing API"),
            (ActionType.DATA_ACCESS, "Read inventory database: 500 widgets"),
            (ActionType.TOOL_USE, "Ran calculator: 500 * 11.75 = 5875.00"),
            (ActionType.DECISION, "Approved purchase under $10k threshold"),
            (ActionType.TRANSACTION, "Placed PO-2024-0042 for 500 widgets"),
            (ActionType.COMMUNICATION, "Sent confirmation email to procurement@"),
            (ActionType.API_CALL, "Called shipment tracking API"),
        ]

        for action_type, summary in actions:
            agentcert.log_action(
                trail=trail,
                agent_keys=agent_keys,
                action_type=action_type,
                action_summary=summary,
            )

        print(f"Logged {len(trail.entries)} actions locally")

        # Submit to service
        submit_result = client.submit_trail(trail)
        print(f"Submitted to service: {submit_result['accepted']} accepted")
        print()

        # ── 5. Force batch ──────────────────────────────────────────────
        batch_result = client.force_batch()
        print(f"Batch created: {batch_result['batch_id'][:32]}...")
        print(f"  Items:    {batch_result['item_count']}")
        print(f"  Anchored: {batch_result['anchored']}")
        print()

        # ── 6. Get proofs ───────────────────────────────────────────────
        entries = agentcert.get_trail_entries(trail)
        entry_5 = entries[5]

        proof = client.get_proof(entry_5.entry_id)
        if proof:
            print(f"Proof for entry #5 ({entry_5.action_summary}):")
            print(f"  Leaf index: {proof.leaf_index}")
            print(f"  Siblings:   {len(proof.siblings)}")
            print(f"  Root:       {proof.root[:32]}...")
            print()

        # ── 7. Verify via service ───────────────────────────────────────
        verification = client.verify_entry(entry_5.entry_id)
        print(f"Verification for entry #5:")
        print(f"  Status: {verification['status']}")
        for check, passed in verification['checks'].items():
            symbol = "PASS" if passed else "FAIL"
            print(f"  [{symbol}] {check}")
        print()

        # ── Stats ───────────────────────────────────────────────────────
        health = client.health()
        print(f"Service health: {health['status']}")
        print(f"  Total entries: {health['entries_total']}")
        print(f"  Pending:       {health['entries_pending']}")
        print(f"  Batches:       {health['batches_total']}")

    # Stop the server
    server.should_exit = True
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
