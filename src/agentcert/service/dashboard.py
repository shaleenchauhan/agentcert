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
        cert=cert,
        meta=meta,
        expired=expired,
        entries=entries,
        total_entries=total_entries,
        page=page,
        total_pages=total_pages,
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
    ))
