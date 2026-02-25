"""FastAPI application for the AgentCert anchoring service.

Provides REST endpoints for certificate registration, entry submission,
Merkle proof retrieval, verification, and service health/stats.
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import agentcert
from agentcert.audit_verify import verify_audit_entry as _verify_audit_entry
from agentcert.batch import verify_batch_proof
from agentcert.exceptions import ServiceError
from agentcert.types import (
    AuditEntry,
    Batch,
    Certificate,
    MerkleProof,
)
from agentcert.verify import check_cert_id, check_signature

from agentcert.service.config import ServiceConfig
from agentcert.service.models import Database
from agentcert.service.scheduler import BatchScheduler


def create_app(config: ServiceConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config: Service configuration. Defaults to ServiceConfig.from_env().

    Returns:
        A configured FastAPI application.
    """
    if config is None:
        config = ServiceConfig.from_env()

    db = Database(config.db_path)
    scheduler = BatchScheduler(db, config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await scheduler.start()
        yield
        await scheduler.stop()
        db.close()

    app = FastAPI(
        title="AgentCert Anchoring Service",
        version=agentcert.__version__,
        lifespan=lifespan,
    )

    # Store refs on app state for access in endpoints
    app.state.db = db
    app.state.config = config
    app.state.scheduler = scheduler

    # ── Certificate Endpoints ───────────────────────────────────────────

    @app.post("/api/v1/certificates")
    async def register_certificate(request: Request) -> dict[str, Any]:
        """Register a certificate with the service."""
        body = await request.json()
        cert_dict = body.get("certificate")
        if not cert_dict:
            raise HTTPException(status_code=400, detail="Missing 'certificate' field")

        # Validate cert_id integrity
        try:
            cert = Certificate.from_dict(cert_dict)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid certificate format: {exc}"
            )

        id_check = check_cert_id(cert)
        if not id_check.passed:
            raise HTTPException(status_code=400, detail=id_check.detail)

        sig_check = check_signature(cert)
        if not sig_check.passed:
            raise HTTPException(status_code=400, detail=sig_check.detail)

        try:
            db.register_certificate(cert_dict)
        except ServiceError:
            raise HTTPException(
                status_code=409,
                detail=f"Certificate {cert.cert_id[:16]}... already registered",
            )

        return {"cert_id": cert.cert_id, "status": "registered"}

    @app.get("/api/v1/certificates/{cert_id}")
    async def get_certificate(cert_id: str) -> dict[str, Any]:
        """Get a registered certificate."""
        cert_dict = db.get_certificate(cert_id)
        if cert_dict is None:
            raise HTTPException(status_code=404, detail="Certificate not found")
        return cert_dict

    # ── Entry Endpoints ─────────────────────────────────────────────────

    @app.post("/api/v1/entries")
    async def submit_entries(request: Request) -> dict[str, Any]:
        """Submit signed audit entries for batching and anchoring."""
        body = await request.json()
        entries_data = body.get("entries")
        if not entries_data or not isinstance(entries_data, list):
            raise HTTPException(
                status_code=400, detail="Missing or invalid 'entries' field"
            )

        accepted: list[str] = []
        rejected = 0
        errors: list[str] = []

        for i, entry_dict in enumerate(entries_data):
            try:
                entry = AuditEntry.from_dict(entry_dict)
            except Exception as exc:
                rejected += 1
                errors.append(f"Entry {i}: invalid format: {exc}")
                continue

            # Verify entry_id integrity
            expected_id = hashlib.sha256(entry.body_bytes()).hexdigest()
            if entry.entry_id != expected_id:
                rejected += 1
                errors.append(f"Entry {i}: entry_id integrity check failed")
                continue

            # Verify agent signature
            sig_result = _verify_audit_entry(entry)
            agent_sig_check = next(
                (c for c in sig_result.checks if c.name == "agent_signature"), None
            )
            if agent_sig_check and not agent_sig_check.passed:
                rejected += 1
                errors.append(f"Entry {i}: agent signature invalid")
                continue

            # Check cert_id references a registered certificate
            cert_dict = db.get_certificate(entry.cert_id)
            if cert_dict is None:
                rejected += 1
                errors.append(
                    f"Entry {i}: cert_id {entry.cert_id[:16]}... not registered"
                )
                continue

            # Check agent_id matches certificate
            if entry.agent_id != cert_dict.get("agent_id"):
                rejected += 1
                errors.append(
                    f"Entry {i}: agent_id does not match certificate"
                )
                continue

            accepted.append(entry.entry_id)

        # Store all accepted entries (duplicates silently skipped)
        accepted_dicts = [
            e for e in entries_data if e.get("entry_id") in accepted
        ]
        inserted = db.store_entries(accepted_dicts)

        return {
            "accepted": len(inserted),
            "rejected": rejected,
            "errors": errors,
            "entry_ids": inserted,
        }

    @app.get("/api/v1/entries/{entry_id}")
    async def get_entry(entry_id: str) -> dict[str, Any]:
        """Get a specific entry."""
        entry_dict = db.get_entry(entry_id)
        if entry_dict is None:
            raise HTTPException(status_code=404, detail="Entry not found")
        return entry_dict

    # ── Trail Endpoints ─────────────────────────────────────────────────

    @app.get("/api/v1/trails/{trail_id}")
    async def get_trail(trail_id: str) -> dict[str, Any]:
        """Get all entries for a trail."""
        entries = db.get_trail_entries(trail_id)
        if not entries:
            raise HTTPException(status_code=404, detail="Trail not found")
        return {"trail_id": trail_id, "entries": entries, "entry_count": len(entries)}

    # ── Proof Endpoints ─────────────────────────────────────────────────

    @app.get("/api/v1/proofs/{entry_id}")
    async def get_proof(entry_id: str) -> dict[str, Any]:
        """Get Merkle proof for an entry."""
        # Check entry exists
        entry_dict = db.get_entry(entry_id)
        if entry_dict is None:
            raise HTTPException(status_code=404, detail="Entry not found")

        proof_record = db.get_proof(entry_id)
        if proof_record is None:
            return {
                "entry_id": entry_id,
                "status": "pending",
                "message": "Entry received but not yet included in a batch",
            }

        batch_dict = db.get_batch(proof_record["batch_id"])
        anchor = None
        if batch_dict and batch_dict.get("anchor_receipt"):
            receipt = batch_dict["anchor_receipt"]
            anchor = {
                "txid": receipt.get("txid"),
                "network": receipt.get("network"),
            }

        return {
            "entry_id": entry_id,
            "batch_id": proof_record["batch_id"],
            "merkle_root": batch_dict["merkle_root"] if batch_dict else None,
            "proof": proof_record["proof"],
            "anchor": anchor,
        }

    # ── Verify Endpoints ────────────────────────────────────────────────

    @app.get("/api/v1/verify/{entry_id}")
    async def verify_entry(entry_id: str) -> dict[str, Any]:
        """Full verification of an entry: integrity + signature + proof + anchor."""
        entry_dict = db.get_entry(entry_id)
        if entry_dict is None:
            raise HTTPException(status_code=404, detail="Entry not found")

        entry = AuditEntry.from_dict(entry_dict)
        checks: dict[str, bool] = {}

        # Entry integrity
        expected_id = hashlib.sha256(entry.body_bytes()).hexdigest()
        checks["entry_integrity"] = entry.entry_id == expected_id

        # Agent signature
        sig_result = _verify_audit_entry(entry)
        agent_sig = next(
            (c for c in sig_result.checks if c.name == "agent_signature"), None
        )
        checks["agent_signature"] = agent_sig.passed if agent_sig else False

        # Cert binding
        cert_dict = db.get_certificate(entry.cert_id)
        checks["cert_binding"] = (
            cert_dict is not None and entry.agent_id == cert_dict.get("agent_id")
        )

        # Merkle proof + anchor
        proof_record = db.get_proof(entry_id)
        batch_dict = None
        if proof_record:
            batch_dict = db.get_batch(proof_record["batch_id"])

        if proof_record and batch_dict:
            proof = MerkleProof.from_dict(proof_record["proof"])
            batch = Batch.from_dict(batch_dict)
            result = verify_batch_proof(entry_id, proof, batch)
            checks["merkle_proof"] = result.proof_valid
            checks["anchor_on_chain"] = (
                batch.anchor_receipt is not None
                and result.anchor_valid is not False
            )
        else:
            checks["merkle_proof"] = False
            checks["anchor_on_chain"] = False

        all_valid = all(checks.values())
        if all_valid:
            status = "VALID"
        elif not proof_record:
            status = "PENDING"
        elif not checks["anchor_on_chain"] and all(
            v for k, v in checks.items() if k != "anchor_on_chain"
        ):
            status = "NOT_ANCHORED"
        else:
            status = "INVALID"

        response: dict[str, Any] = {
            "entry_id": entry_id,
            "status": status,
            "checks": checks,
        }

        if cert_dict:
            meta = cert_dict.get("agent_metadata", {})
            response["certificate"] = {
                "cert_id": cert_dict["cert_id"],
                "agent_name": meta.get("name"),
                "creator_id": cert_dict.get("creator_id"),
            }

        if batch_dict:
            response["batch"] = {
                "batch_id": batch_dict["batch_id"],
                "merkle_root": batch_dict["merkle_root"],
                "anchored_at": batch_dict.get("timestamp"),
            }
            if batch_dict.get("anchor_receipt"):
                receipt = batch_dict["anchor_receipt"]
                network = receipt.get("network", "testnet")
                txid = receipt.get("txid", "")
                explorer_base = (
                    "https://blockstream.info/testnet/tx"
                    if network == "testnet"
                    else "https://blockstream.info/tx"
                )
                response["anchor"] = {
                    "txid": txid,
                    "network": network,
                    "explorer_url": f"{explorer_base}/{txid}",
                }

        return response

    # ── Batch Endpoints ─────────────────────────────────────────────────

    @app.get("/api/v1/batches/latest")
    async def get_latest_batch() -> dict[str, Any]:
        """Get the most recent batch."""
        batch_dict = db.get_latest_batch()
        if batch_dict is None:
            raise HTTPException(status_code=404, detail="No batches yet")
        return batch_dict

    @app.get("/api/v1/batches/{batch_id}")
    async def get_batch(batch_id: str) -> dict[str, Any]:
        """Get batch details."""
        batch_dict = db.get_batch(batch_id)
        if batch_dict is None:
            raise HTTPException(status_code=404, detail="Batch not found")
        return batch_dict

    # ── Admin Endpoints ─────────────────────────────────────────────────

    @app.post("/api/v1/admin/force-batch")
    async def force_batch() -> dict[str, Any]:
        """Force an immediate batch cycle."""
        batch = await scheduler.force_batch()
        if batch is None:
            return {"status": "no_entries", "message": "No entries to batch"}
        return {
            "status": "batched",
            "batch_id": batch.batch_id,
            "merkle_root": batch.merkle_root,
            "item_count": batch.item_count,
            "anchored": batch.anchor_receipt is not None,
        }

    @app.post("/api/v1/admin/import-batch")
    async def import_batch(request: Request) -> dict[str, Any]:
        """Import a pre-anchored batch with Merkle proofs.

        Accepts a batch dict (with anchor_receipt) and a proofs dict
        (entry_id → proof), stores the batch, marks entries as batched,
        and stores all proofs.
        """
        body = await request.json()
        batch_dict = body.get("batch")
        proofs_dict = body.get("proofs")

        if not batch_dict:
            raise HTTPException(status_code=400, detail="Missing 'batch' field")
        if not proofs_dict or not isinstance(proofs_dict, dict):
            raise HTTPException(status_code=400, detail="Missing or invalid 'proofs' field")

        batch_id = batch_dict["batch_id"]
        item_hashes = batch_dict.get("item_hashes", [])

        # Store batch (skip if already exists)
        try:
            db.store_batch(batch_dict)
        except Exception:
            # Already exists — update anchor if needed
            existing = db.get_batch(batch_id)
            if existing and not existing.get("anchor_receipt") and batch_dict.get("anchor_receipt"):
                db.update_batch_anchor(batch_id, batch_dict["anchor_receipt"])

        # Mark entries as batched
        entries_marked = 0
        for entry_id in item_hashes:
            try:
                db.mark_entries_batched([entry_id], batch_id)
                entries_marked += 1
            except Exception:
                continue

        # Store proofs
        proof_records = []
        for entry_id, proof_data in proofs_dict.items():
            proof_records.append({
                "entry_id": entry_id,
                "batch_id": batch_id,
                "proof": proof_data,
            })
        db.store_proofs(proof_records)

        return {
            "status": "imported",
            "batch_id": batch_id,
            "merkle_root": batch_dict.get("merkle_root"),
            "entries_marked": entries_marked,
            "proofs_stored": len(proof_records),
        }

    # ── Health / Stats ──────────────────────────────────────────────────

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        """Health check."""
        stats = db.get_stats()
        last_anchor = stats["last_anchor"]
        last_anchor_str = (
            datetime.fromtimestamp(last_anchor, tz=timezone.utc).isoformat()
            if last_anchor
            else None
        )
        return {
            "status": "healthy",
            "version": agentcert.__version__,
            "entries_total": stats["entries_total"],
            "entries_pending": stats["entries_pending"],
            "batches_total": stats["batches_total"],
            "last_anchor": last_anchor_str,
        }

    @app.get("/api/v1/stats")
    async def stats() -> dict[str, Any]:
        """Service statistics."""
        return db.get_stats()

    # ── Dashboard (HTML) ─────────────────────────────────────────────

    from agentcert.service.dashboard import dashboard_router

    static_dir = Path(__file__).parent / "static"
    app.mount("/dashboard/static", StaticFiles(directory=str(static_dir)), name="static")
    app.include_router(dashboard_router)

    return app
