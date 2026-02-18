"""AgentCert Audit Trail Demo — create, log, verify, and inspect an audit trail.

Demonstrates the full audit trail lifecycle:
    1. Key generation and certificate creation
    2. Audit trail creation (bound to certificate)
    3. Logging agent actions (API calls, decisions, transactions)
    4. Single-entry verification
    5. Full trail verification (11 checks)
    6. Trail inspection and filtering
    7. Save and reload

Run:
    python examples/audit_trail_demo.py
"""

import agentcert


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def print_checks(
    checks: tuple[agentcert.AuditVerificationCheck, ...],
) -> None:
    for check in checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  [{status}] {check.name}: {check.detail}")


def main() -> None:
    # ── Step 1: Setup ─────────────────────────────────────────────────

    section("Step 1: Key Generation & Certificate")

    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()

    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="procurement-agent-v1",
        platform="langchain",
        model_hash="sha256:a1b2c3d4e5f67890abcdef1234567890",
        capabilities=["procurement", "negotiation", "invoicing"],
        constraints=["max-transaction-50000-usd"],
        risk_tier=3,
        expires_days=90,
    )

    print(f"Certificate: {cert.cert_id[:16]}...")
    print(f"Agent:       {cert.agent_metadata.name}")
    print(f"Agent ID:    {cert.agent_id[:16]}...")

    # ── Step 2: Create Audit Trail ────────────────────────────────────

    section("Step 2: Create Audit Trail")

    trail = agentcert.create_audit_trail(cert, agent_keys)

    print(f"Trail ID:    {trail.trail_id[:16]}...")
    print(f"Bound to:    cert {trail.cert_id[:16]}...")
    print(f"Agent:       {trail.agent_id[:16]}...")
    print(f"Entries:     {len(trail.entries)}")

    # ── Step 3: Log Agent Actions ─────────────────────────────────────

    section("Step 3: Log Agent Actions")

    # Action 1: API call
    e1 = agentcert.log_action(
        trail, agent_keys,
        action_type=agentcert.ActionType.API_CALL,
        action_summary="Queried vendor pricing API",
        action_detail={"url": "https://api.vendors.example/prices", "status": 200},
    )
    print(f"[seq {e1.sequence}] {e1.action_summary}")
    print(f"         entry_id: {e1.entry_id[:16]}...")
    print(f"         previous: None (first entry)")

    # Action 2: Decision
    e2 = agentcert.log_action(
        trail, agent_keys,
        action_type=agentcert.ActionType.DECISION,
        action_summary="Selected cheapest vendor: Acme Corp",
        action_detail={"vendor": "Acme Corp", "price_per_unit": 12.50},
    )
    print(f"[seq {e2.sequence}] {e2.action_summary}")
    print(f"         entry_id: {e2.entry_id[:16]}...")
    print(f"         previous: {e2.previous_entry_id[:16]}...")

    # Action 3: Transaction
    e3 = agentcert.log_action(
        trail, agent_keys,
        action_type=agentcert.ActionType.TRANSACTION,
        action_summary="Placed purchase order for 500 widgets",
        action_detail={"vendor": "Acme Corp", "quantity": 500, "total": 6250.00},
    )
    print(f"[seq {e3.sequence}] {e3.action_summary}")
    print(f"         entry_id: {e3.entry_id[:16]}...")
    print(f"         previous: {e3.previous_entry_id[:16]}...")

    # Action 4: Communication
    e4 = agentcert.log_action(
        trail, agent_keys,
        action_type=agentcert.ActionType.COMMUNICATION,
        action_summary="Sent order confirmation to procurement team",
    )
    print(f"[seq {e4.sequence}] {e4.action_summary}")
    print(f"         entry_id: {e4.entry_id[:16]}...")
    print(f"         previous: {e4.previous_entry_id[:16]}...")

    print(f"\nTotal entries logged: {len(trail.entries)}")

    # ── Step 4: Verify Single Entry ───────────────────────────────────

    section("Step 4: Verify Single Entry")

    entry_result = agentcert.verify_audit_entry(trail.entries[2], cert)
    print(f"Entry: seq {trail.entries[2].sequence} — {trail.entries[2].action_summary}")
    print_checks(entry_result.checks)
    print(f"\nStatus: {entry_result.status}")

    # ── Step 5: Verify Full Trail ─────────────────────────────────────

    section("Step 5: Verify Full Trail (11 checks)")

    trail_result = agentcert.verify_audit_trail(trail, cert)
    print_checks(trail_result.checks)
    print(f"\nTrail ID:    {trail_result.trail_id[:16]}...")
    print(f"Entries:     {trail_result.entry_count}")
    print(f"Status:      {trail_result.status}")

    # ── Step 6: Inspect & Filter ──────────────────────────────────────

    section("Step 6: Inspect & Filter")

    info = agentcert.get_trail_info(trail)
    print(f"Trail info:")
    print(f"  trail_id:    {info.trail_id[:16]}...")
    print(f"  cert_id:     {info.cert_id[:16]}...")
    print(f"  entries:     {info.entry_count}")
    print(f"  created:     {info.created}")
    print(f"  last_entry:  {info.last_entry}")

    # Filter by action type
    api_calls = agentcert.get_trail_entries(
        trail, action_type=agentcert.ActionType.API_CALL,
    )
    print(f"\nAPI_CALL entries: {len(api_calls)}")
    for e in api_calls:
        print(f"  [seq {e.sequence}] {e.action_summary}")

    decisions = agentcert.get_trail_entries(
        trail, action_type=agentcert.ActionType.DECISION,
    )
    print(f"\nDECISION entries: {len(decisions)}")
    for e in decisions:
        print(f"  [seq {e.sequence}] {e.action_summary}")

    transactions = agentcert.get_trail_entries(
        trail, action_type=agentcert.ActionType.TRANSACTION,
    )
    print(f"\nTRANSACTION entries: {len(transactions)}")
    for e in transactions:
        print(f"  [seq {e.sequence}] {e.action_summary}")

    # Filter by sequence range
    recent = agentcert.get_trail_entries(trail, start=2)
    print(f"\nEntries from seq 2 onward: {len(recent)}")
    for e in recent:
        print(f"  [seq {e.sequence}] {e.action_summary}")

    # ── Step 7: Save & Reload ─────────────────────────────────────────

    section("Step 7: Save & Reload")

    agentcert.save_trail(trail, "demo-trail.json")
    agentcert.save_certificate(cert, "demo-cert.json")
    print("Saved: demo-trail.json, demo-cert.json")

    # Reload and re-verify
    loaded_trail = agentcert.load_trail("demo-trail.json")
    loaded_cert = agentcert.load_certificate("demo-cert.json")
    reload_result = agentcert.verify_audit_trail(loaded_trail, loaded_cert)
    print(f"\nReloaded and re-verified: {reload_result.status}")
    print(f"Entries preserved: {reload_result.entry_count}")

    print(f"\nDone. Audit trail lifecycle complete.")


if __name__ == "__main__":
    main()
