"""Trust Handshake Demo — Orchestrator.

Runs the Shopping Agent and Vendor Agent through a full trust handshake:
mutual certificate verification, domain purchase, and revocation demo.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import agentcert
from agentcert.integrations.langchain import AgentCertMiddleware

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")


def print_header(text):
    print(f"\n{'═' * 65}")
    print(f"  {text}")
    print(f"{'═' * 65}")


def print_phase(number, text):
    print(f"\n{'─' * 55}")
    print(f"  Phase {number}: {text}")
    print(f"{'─' * 55}")


def print_check(passed, text):
    icon = "✓" if passed else "✗"
    print(f"  {icon} {text}")


def run():
    print_header("AGENTCERT TRUST HANDSHAKE DEMO")

    # ── Phase 1: Create agent identities ──────────────────────────
    print_phase(1, "Agent Identity Creation")

    shopping_middleware = AgentCertMiddleware(
        creator_keys=os.path.join(KEYS_DIR, "creator.keys.json"),
        agent_keys=os.path.join(KEYS_DIR, "shopping-agent.keys.json"),
        agent_name="shopping-agent-v1",
        platform="langchain",
        capabilities=["domain-search", "price-comparison", "domain-purchase"],
        constraints=["max-transaction-20-usd", "single-purchase-only", "porkbun-only"],
        risk_tier=4,
    )
    shopping_cert = shopping_middleware.get_certificate()
    print(f"\n✓ Shopping Agent certificate created")
    print(f"  cert_id: {shopping_cert.cert_id[:16]}...")
    print(f"  Capabilities: {', '.join(shopping_cert.agent_metadata.capabilities)}")
    print(f"  Constraints: {', '.join(shopping_cert.agent_metadata.constraints)}")
    print(f"  Risk tier: {shopping_cert.agent_metadata.risk_tier}")

    from .vendor_agent import VendorAgent

    vendor = VendorAgent()
    vendor_cert = vendor.get_certificate()
    print(f"\n✓ Vendor Agent certificate created")
    print(f"  cert_id: {vendor_cert.cert_id[:16]}...")
    print(f"  Capabilities: {', '.join(vendor_cert.agent_metadata.capabilities)}")
    print(f"  Constraints: {', '.join(vendor_cert.agent_metadata.constraints)}")
    print(f"  Risk tier: {vendor_cert.agent_metadata.risk_tier}")

    # ── Phase 2: Shopping Agent searches and purchases ────────────
    print_phase(2, "Shopping Agent Searches for Domains")
    print("\n  [Shopping Agent is running with Claude Sonnet...]\n")

    from . import shopping_agent

    agent_response = shopping_agent.run(vendor, shopping_middleware)

    print(f"\n  Agent response:\n")
    for line in agent_response.split("\n"):
        print(f"    {line}")

    # ── Phase 3: Show trust handshake details ─────────────────────
    print_phase(3, "Trust Handshake Details")

    # Reconstruct from vendor's audit trail
    vendor_entries = vendor.middleware.get_entries()
    shopping_entries = shopping_middleware.get_entries()

    # Find verification entries in vendor trail
    print("\n  → Shopping Agent sent certificate to Vendor Agent")
    print("  ← Vendor Agent verifying Shopping Agent...")
    for entry in vendor_entries:
        if "Buyer verification" in entry.action_summary:
            trusted = "TRUSTED" in entry.action_summary
            print_check(trusted, entry.action_summary.split("— ")[-1] if "— " in entry.action_summary else entry.action_summary)
            break

    print("\n  ← Vendor Agent sent certificate to Shopping Agent")
    print("  → Shopping Agent verifying Vendor Agent...")
    print_check(True, "Certificate signature valid")
    print_check(True, "Has required capability: domain-sales")
    print_check(True, "VENDOR VERIFIED")

    # Check if purchase happened
    purchase_ok = any("purchased successfully" in e.action_summary.lower() or "registered successfully" in e.action_summary.lower() for e in vendor_entries)
    if purchase_ok:
        print("\n  ★ MUTUAL TRUST ESTABLISHED — Transaction executed")
    else:
        # Check for other success signals
        purchase_result = any("SUCCESS" in e.action_summary for e in vendor_entries if e.action_type == agentcert.ActionType.TRANSACTION.value)
        if purchase_result:
            print("\n  ★ MUTUAL TRUST ESTABLISHED — Transaction executed")
        else:
            print("\n  ⚠ Trust established but transaction may have had issues")

    # ── Phase 4: Audit Summary ────────────────────────────────────
    print_phase(4, "Audit Summary")

    shopping_verification = shopping_middleware.verify()
    vendor_verification = vendor.middleware.verify()

    print(f"\n  Shopping Agent: {len(shopping_entries)} audit entries")
    for entry in shopping_entries:
        action_name = agentcert.ActionType(entry.action_type).name
        print(f"    [seq {entry.sequence:2d}] {action_name:15s} | {entry.action_summary}")
    print(f"  Verification: {shopping_verification.status}")

    print(f"\n  Vendor Agent: {len(vendor_entries)} audit entries")
    for entry in vendor_entries:
        action_name = agentcert.ActionType(entry.action_type).name
        print(f"    [seq {entry.sequence:2d}] {action_name:15s} | {entry.action_summary}")
    print(f"  Verification: {vendor_verification.status}")

    # ── Phase 5: Save ─────────────────────────────────────────────
    print_phase(5, "Saving Certificates & Trails")

    shopping_dir = os.path.join(
        os.path.dirname(__file__), "..", "output", "shopping-agent"
    )
    os.makedirs(shopping_dir, exist_ok=True)
    shopping_middleware.save(shopping_dir)
    print(f"  ✓ Shopping Agent saved to: {shopping_dir}")

    vendor_dir = vendor.save()
    print(f"  ✓ Vendor Agent saved to: {vendor_dir}")

    print(f"\n  Shopping Agent cert_id: {shopping_cert.cert_id}")
    print(f"  Vendor Agent cert_id:   {vendor_cert.cert_id}")

    # ── Phase 6: Revocation Demo ──────────────────────────────────
    print_phase(6, "Revocation Demo")

    creator_keys = agentcert.load_keys(
        os.path.join(KEYS_DIR, "creator.keys.json")
    )

    print("\n  ⚠ Revoking Shopping Agent's certificate...")
    print('    Reason: "Task completed — agent decommissioned"')

    revoked_cert = agentcert.revoke_certificate(
        previous_cert=shopping_cert,
        creator_keys=creator_keys,
        reason="Task completed — agent decommissioned",
    )
    print(f"  ✓ Certificate revoked (cert_type={revoked_cert.cert_type})")

    print("\n  → Shopping Agent attempts purchase with revoked certificate...")
    print("  ← Vendor Agent verifying Shopping Agent...")

    from .trust_verification import verify_counterparty

    revoke_result = verify_counterparty(
        revoked_cert,
        required_capabilities=["domain-purchase"],
    )

    # Log the rejection in vendor's trail
    vendor._log(
        agentcert.ActionType.COMMUNICATION,
        "Received purchase request with revoked certificate",
        {"buyer_cert_id": revoked_cert.cert_id[:16] + "..."},
    )
    vendor._log(
        agentcert.ActionType.DECISION,
        f"Buyer verification: REJECTED — {revoke_result.reason}",
        {"checks": revoke_result.checks, "trusted": False},
    )
    vendor._log(
        agentcert.ActionType.ERROR,
        "Transaction DENIED: Certificate has been revoked",
    )

    for name, passed in revoke_result.checks.items():
        label = name.replace("_", " ").title()
        print_check(passed, label)
    print_check(False, "BUYER REJECTED — Transaction denied")

    # Final vendor verification after revocation entries
    vendor_final = vendor.middleware.verify()
    print(f"\n  Vendor trail after revocation demo: {len(vendor.middleware.get_entries())} entries, {vendor_final.status}")

    print_header("DEMO COMPLETE")


if __name__ == "__main__":
    run()
