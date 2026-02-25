"""Dashboard routes for the AgentCert anchoring service.

Server-rendered HTML pages using Jinja2 templates. Mounted on the existing
FastAPI app under ``/dashboard``.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

import agentcert
from agentcert.service.models import Database
from agentcert.types import ActionType

_TEMPLATE_DIR = Path(__file__).parent / "templates"

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# ── Explainer Texts ─────────────────────────────────────────────────────────

_EXPLAINER = {
    "overview": (
        "The cards at the top show how many AI agents are registered, how many actions "
        "have been audited, how many Merkle batches have been created, and when the last "
        "batch was anchored to Bitcoin. Below, Recent Activity shows the latest actions "
        "across all agents \u2014 each one is cryptographically signed and tamper-proof. "
        "Recent Batches shows groups of entries that have been anchored to the Bitcoin "
        "blockchain together."
    ),
    "agents": (
        "Each row is a registered AI agent. The name links to its full certificate and "
        "audit trail. Platform shows which framework it runs on. Risk Tier indicates the "
        "agent\u2019s authorization level \u2014 more dots means higher risk. Entries counts "
        "how many audited actions that agent has performed. All entries are "
        "cryptographically signed and anchored to Bitcoin."
    ),
    "agent_detail": (
        "At the top is this agent\u2019s identity certificate \u2014 who created it, what "
        "it\u2019s allowed to do (capabilities), what it\u2019s restricted from (constraints), "
        "and its risk tier. Below is the complete audit trail: every action this agent "
        "took, in order. Signed = the agent cryptographically signed this entry. "
        "Batched = it\u2019s included in a Merkle tree. Anchored = that tree is recorded "
        "on the Bitcoin blockchain. Click any entry to see full verification."
    ),
    "entry_detail": (
        "This is a single action taken by an AI agent. Entry Information shows what "
        "happened \u2014 the action type, a summary, timestamp, and the agent\u2019s "
        "cryptographic signature. Verification runs five independent checks: the "
        "content hasn\u2019t been tampered with (integrity), the agent actually signed it "
        "(signature), the agent\u2019s certificate is valid (binding), it\u2019s in a Merkle "
        "batch (proof), and that batch is on the Bitcoin blockchain (anchor). "
        "All green = verified and permanent. Below that, Merkle Proof shows this "
        "entry\u2019s position in the batch \u2014 the leaf hash and the sibling hashes that "
        "form a path up to the Merkle root. Bitcoin Anchor shows the on-chain "
        "transaction where that root was recorded \u2014 the txid, block height, and "
        "confirmations. To verify the anchor yourself: copy the Merkle Root shown on "
        "this page, click \u2018View on Blockchain\u2019 to open Blockstream Explorer, click "
        "\u2018Details\u2019 on the transaction, and confirm the Merkle Root matches the "
        "content inside the OP_RETURN output."
    ),
    "entries": (
        "Every row is an audited action taken by an AI agent \u2014 cryptographically signed "
        "and anchored to Bitcoin. Use the dropdown to filter by agent. Click any summary "
        "to see full verification details for that entry, or click the agent name to see "
        "its certificate and complete audit trail."
    ),
    "batches": (
        "Each row is a Merkle batch \u2014 a group of audit entries combined into a single "
        "cryptographic tree. The Merkle Root is the tree\u2019s fingerprint. When it says "
        "\u2018Anchored\u2019, that root hash has been written to the Bitcoin blockchain, making "
        "every entry in the batch permanently verifiable. One Bitcoin transaction secures "
        "all entries in the batch."
    ),
    "batch_detail": (
        "This batch combined the listed entries into a single Merkle tree. The Merkle "
        "Root is the tree\u2019s fingerprint \u2014 it\u2019s been written to the Bitcoin blockchain "
        "in the transaction shown. Click any entry to see its individual verification "
        "and its path through the Merkle tree to this root."
    ),
    "verify": (
        "Paste any entry ID (the SHA-256 hex string from an entry detail page) and hit "
        "Verify. This runs five verification checks on the entry. To complete all five, "
        "the system needs: the full entry content (to recompute the hash and check "
        "integrity), the agent\u2019s public key (to verify the signature), the agent\u2019s "
        "certificate (to confirm binding), the Merkle proof \u2014 the leaf hash and sibling "
        "path (to recompute the Merkle root), and the Bitcoin transaction ID (to look up "
        "the OP_RETURN on-chain and confirm the root matches). Currently all of this data "
        "is served by AgentCert \u2014 but every check is cryptographic, so AgentCert "
        "can\u2019t forge it. If any entry, signature, or proof were altered, verification "
        "would fail. The Bitcoin anchor is independently checkable on any block explorer."
    ),
}

# ── Helpers ──────────────────────────────────────────────────────────────────

ACTION_TYPE_LABELS = {
    ActionType.API_CALL: ("API_CALL", "\U0001f916"),
    ActionType.TOOL_USE: ("TOOL_USE", "\U0001f527"),
    ActionType.DECISION: ("DECISION", "\U0001f9e0"),
    ActionType.DATA_ACCESS: ("DATA_ACCESS", "\U0001f4c2"),
    ActionType.TRANSACTION: ("TRANSACTION", "\U0001f4b8"),
    ActionType.COMMUNICATION: ("COMMUNICATION", "\U0001f4e8"),
    ActionType.ERROR: ("ERROR", "\u26a0\ufe0f"),
    ActionType.CUSTOM: ("CUSTOM", "\u2699\ufe0f"),
}


def _action_label(action_type: int) -> str:
    """Return a label string for an action type code."""
    entry = ACTION_TYPE_LABELS.get(ActionType(action_type))
    if entry:
        return f"{entry[1]} {entry[0]}"
    return str(action_type)


def _time_ago(ts: int | float | None) -> str:
    """Return a human-readable relative time string."""
    if ts is None:
        return "Never"
    diff = int(time.time()) - int(ts)
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"


def _format_ts(ts: int | float | None) -> str:
    """Format a Unix timestamp for display."""
    if ts is None:
        return "—"
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _db(request: Request) -> Database:
    """Get the database from the app state."""
    return request.app.state.db


def _ctx(request: Request, **kwargs: Any) -> dict[str, Any]:
    """Build the template context with common values."""
    return {
        "request": request,
        "version": agentcert.__version__,
        "action_label": _action_label,
        "time_ago": _time_ago,
        "format_ts": _format_ts,
        **kwargs,
    }


# ── Routes ───────────────────────────────────────────────────────────────────


@dashboard_router.get("/")
async def overview(request: Request):
    """Overview / home page."""
    db = _db(request)
    stats = db.get_stats()
    recent_entries = db.get_recent_entries(limit=10)
    recent_batches = db.get_recent_batches(limit=5)

    # Enrich entries with agent name from certificate
    for entry in recent_entries:
        cert = db.get_certificate(entry.get("cert_id", ""))
        if cert:
            meta = cert.get("agent_metadata", {})
            entry["_agent_name"] = meta.get("name", "Unknown")
        else:
            entry["_agent_name"] = "Unknown"

    return templates.TemplateResponse(request, "overview.html", _ctx(
        request,
        active_page="overview",
        explainer_text=_EXPLAINER["overview"],
        stats=stats,
        recent_entries=recent_entries,
        recent_batches=recent_batches,
    ))


@dashboard_router.get("/agents")
async def agents_list(request: Request):
    """Agent list page."""
    db = _db(request)
    certs = db.get_all_certificates()

    # Enrich with entry count and last active
    agents = []
    for cert in certs:
        cert_id = cert["cert_id"]
        entry_count = db.get_entry_count_by_cert(cert_id)
        last_active = db.get_last_active_by_cert(cert_id)
        meta = cert.get("agent_metadata", {})
        now = int(time.time())
        expired = cert.get("expires", 0) < now

        agents.append({
            "cert_id": cert_id,
            "name": meta.get("name", "Unknown"),
            "platform": meta.get("platform", "—"),
            "risk_tier": meta.get("risk_tier", 0),
            "entry_count": entry_count,
            "last_active": last_active,
            "expired": expired,
        })

    return templates.TemplateResponse(request, "agents.html", _ctx(
        request,
        active_page="agents",
        explainer_text=_EXPLAINER["agents"],
        agents=agents,
    ))


@dashboard_router.get("/agents/{cert_id}")
async def agent_detail(request: Request, cert_id: str):
    """Agent detail page — certificate info + audit trail."""
    db = _db(request)
    cert = db.get_certificate(cert_id)
    if cert is None:
        return templates.TemplateResponse(request, "base.html", _ctx(
            request, active_page="agents",
        ), status_code=404)

    # Pagination
    page = int(request.query_params.get("page", "1"))
    per_page = 50
    offset = (page - 1) * per_page
    total_entries = db.get_entry_count_by_cert(cert_id)
    entries = db.get_entries_by_cert(cert_id, offset=offset, limit=per_page)
    total_pages = max(1, (total_entries + per_page - 1) // per_page)

    # Check each entry for batch/anchor status
    for entry in entries:
        entry_id = entry.get("entry_id", "")
        proof = db.get_proof(entry_id)
        entry["_batched"] = proof is not None
        entry["_anchored"] = False
        if proof:
            batch = db.get_batch(proof["batch_id"])
            if batch and batch.get("anchor_receipt"):
                entry["_anchored"] = True

    meta = cert.get("agent_metadata", {})
    now = int(time.time())
    expired = cert.get("expires", 0) < now

    return templates.TemplateResponse(request, "agent_detail.html", _ctx(
        request,
        active_page="agents",
        explainer_text=_EXPLAINER["agent_detail"],
        cert=cert,
        meta=meta,
        expired=expired,
        entries=entries,
        total_entries=total_entries,
        page=page,
        total_pages=total_pages,
    ))


@dashboard_router.get("/entries")
async def entries_list(request: Request):
    """All entries page with optional agent and status filters."""
    db = _db(request)
    filter_cert = request.query_params.get("agent", "")
    filter_status = request.query_params.get("status", "")

    entries = db.get_all_entries(
        cert_id=filter_cert or None,
        status=filter_status or None,
    )

    # Build agent list for the filter dropdown
    certs = db.get_all_certificates()
    agents = []
    for cert in certs:
        meta = cert.get("agent_metadata", {})
        agents.append({
            "cert_id": cert["cert_id"],
            "name": meta.get("name", "Unknown"),
        })

    # Enrich entries with agent name
    cert_cache: dict[str, str] = {a["cert_id"]: a["name"] for a in agents}
    for entry in entries:
        entry["_agent_name"] = cert_cache.get(entry.get("cert_id", ""), "Unknown")

    return templates.TemplateResponse(request, "entries.html", _ctx(
        request,
        active_page="entries",
        explainer_text=_EXPLAINER["entries"],
        entries=entries,
        agents=agents,
        filter_cert=filter_cert,
        filter_status=filter_status,
    ))


@dashboard_router.get("/entries/{entry_id}")
async def entry_detail(request: Request, entry_id: str):
    """Entry detail page — full verification view."""
    db = _db(request)
    entry = db.get_entry(entry_id)
    if entry is None:
        return templates.TemplateResponse(request, "base.html", _ctx(
            request, active_page="",
        ), status_code=404)

    cert = db.get_certificate(entry.get("cert_id", ""))
    agent_name = "Unknown"
    if cert:
        meta = cert.get("agent_metadata", {})
        agent_name = meta.get("name", "Unknown")

    # Get proof and batch info
    proof_record = db.get_proof(entry_id)
    batch = None
    proof = None
    anchor = None
    if proof_record:
        proof = proof_record["proof"]
        batch = db.get_batch(proof_record["batch_id"])
        if batch and batch.get("anchor_receipt"):
            receipt = batch["anchor_receipt"]
            network = receipt.get("network", "testnet")
            txid = receipt.get("txid", "")
            explorer_base = (
                "https://blockstream.info/testnet/tx"
                if network == "testnet"
                else "https://blockstream.info/tx"
            )
            anchor = {
                "txid": txid,
                "network": network,
                "explorer_url": f"{explorer_base}/{txid}",
                "op_return_hex": receipt.get("op_return_hex", ""),
            }

    return templates.TemplateResponse(request, "entry_detail.html", _ctx(
        request,
        active_page="",
        explainer_text=_EXPLAINER["entry_detail"],
        entry=entry,
        agent_name=agent_name,
        cert=cert,
        proof=proof,
        batch=batch,
        anchor=anchor,
    ))


@dashboard_router.get("/batches")
async def batches_list(request: Request):
    """Batches list page."""
    db = _db(request)
    batches = db.get_all_batches()

    return templates.TemplateResponse(request, "batches.html", _ctx(
        request,
        active_page="batches",
        explainer_text=_EXPLAINER["batches"],
        batches=batches,
    ))


@dashboard_router.get("/batches/{batch_id}")
async def batch_detail(request: Request, batch_id: str):
    """Batch detail page."""
    db = _db(request)
    batch = db.get_batch(batch_id)
    if batch is None:
        return templates.TemplateResponse(request, "base.html", _ctx(
            request, active_page="batches",
        ), status_code=404)

    entries = db.get_entries_by_batch(batch_id)
    anchor = None
    if batch.get("anchor_receipt"):
        receipt = batch["anchor_receipt"]
        network = receipt.get("network", "testnet")
        txid = receipt.get("txid", "")
        explorer_base = (
            "https://blockstream.info/testnet/tx"
            if network == "testnet"
            else "https://blockstream.info/tx"
        )
        anchor = {
            "txid": txid,
            "network": network,
            "explorer_url": f"{explorer_base}/{txid}",
        }

    # Get agent names for each entry
    for entry in entries:
        cert = db.get_certificate(entry.get("cert_id", ""))
        if cert:
            meta = cert.get("agent_metadata", {})
            entry["_agent_name"] = meta.get("name", "Unknown")
        else:
            entry["_agent_name"] = "Unknown"

    return templates.TemplateResponse(request, "batch_detail.html", _ctx(
        request,
        active_page="batches",
        explainer_text=_EXPLAINER["batch_detail"],
        batch=batch,
        entries=entries,
        anchor=anchor,
    ))


@dashboard_router.get("/verify")
async def verify_page(request: Request):
    """Verification tool page."""
    return templates.TemplateResponse(request, "verify.html", _ctx(
        request,
        active_page="verify",
        explainer_text=_EXPLAINER["verify"],
    ))
