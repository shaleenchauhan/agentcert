"""SQLite database layer for the AgentCert anchoring service.

Simple functions wrapping sqlite3. No ORM. Provides CRUD for certificates,
entries, batches, and proofs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from agentcert.exceptions import ServiceError


_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    cert_id TEXT PRIMARY KEY,
    certificate_json TEXT NOT NULL,
    registered_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    entry_id TEXT PRIMARY KEY,
    trail_id TEXT NOT NULL,
    cert_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    entry_json TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    batch_id TEXT,
    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    item_hashes_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    anchor_receipt_json TEXT,
    anchored_at INTEGER
);

CREATE TABLE IF NOT EXISTS proofs (
    entry_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    proof_json TEXT NOT NULL,
    PRIMARY KEY (entry_id, batch_id),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id),
    FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);

CREATE INDEX IF NOT EXISTS idx_entries_trail ON entries(trail_id);
CREATE INDEX IF NOT EXISTS idx_entries_cert ON entries(cert_id);
CREATE INDEX IF NOT EXISTS idx_entries_batch ON entries(batch_id);
"""


class Database:
    """SQLite database for the AgentCert anchoring service.

    Args:
        db_path: Path to the SQLite database file. Parent directories are
            created automatically. Use ``":memory:"`` for in-memory databases.
    """

    def __init__(self, db_path: str) -> None:
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── Certificates ────────────────────────────────────────────────────────

    def register_certificate(self, cert_dict: dict[str, Any]) -> str:
        """Register a certificate.

        Args:
            cert_dict: The certificate as a dict (from Certificate.to_dict()).

        Returns:
            The cert_id.

        Raises:
            ServiceError: If the cert_id already exists.
        """
        cert_id = cert_dict["cert_id"]
        try:
            self._conn.execute(
                "INSERT INTO certificates (cert_id, certificate_json, registered_at) "
                "VALUES (?, ?, ?)",
                (cert_id, json.dumps(cert_dict, sort_keys=True, separators=(",", ":")),
                 int(time.time())),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            raise ServiceError(f"Certificate {cert_id[:16]}... already registered")
        return cert_id

    def get_certificate(self, cert_id: str) -> dict[str, Any] | None:
        """Get a certificate by cert_id.

        Returns:
            The certificate dict, or None if not found.
        """
        row = self._conn.execute(
            "SELECT certificate_json FROM certificates WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["certificate_json"])

    # ── Entries ─────────────────────────────────────────────────────────────

    def store_entries(self, entries: list[dict[str, Any]]) -> list[str]:
        """Store one or more audit entries.

        Duplicate entries (by entry_id) are silently skipped.

        Args:
            entries: List of entry dicts (from AuditEntry.to_dict()).

        Returns:
            List of entry_ids that were actually inserted.
        """
        inserted: list[str] = []
        now = int(time.time())
        for entry in entries:
            entry_id = entry["entry_id"]
            try:
                self._conn.execute(
                    "INSERT INTO entries "
                    "(entry_id, trail_id, cert_id, agent_id, sequence, entry_json, received_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry_id,
                        entry["trail_id"],
                        entry["cert_id"],
                        entry["agent_id"],
                        entry["sequence"],
                        json.dumps(entry, sort_keys=True, separators=(",", ":")),
                        now,
                    ),
                )
                inserted.append(entry_id)
            except sqlite3.IntegrityError:
                continue
        self._conn.commit()
        return inserted

    def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        """Get an entry by entry_id.

        Returns:
            The entry dict, or None if not found.
        """
        row = self._conn.execute(
            "SELECT entry_json FROM entries WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["entry_json"])

    def get_trail_entries(self, trail_id: str) -> list[dict[str, Any]]:
        """Get all entries for a trail, ordered by sequence.

        Args:
            trail_id: The trail identifier.

        Returns:
            List of entry dicts, ordered by sequence.
        """
        rows = self._conn.execute(
            "SELECT entry_json FROM entries WHERE trail_id = ? ORDER BY sequence",
            (trail_id,),
        ).fetchall()
        return [json.loads(row["entry_json"]) for row in rows]

    def get_unbatched_entries(self, limit: int = 10000) -> list[dict[str, Any]]:
        """Get entries that haven't been assigned to a batch yet.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of entry dicts.
        """
        rows = self._conn.execute(
            "SELECT entry_json FROM entries WHERE batch_id IS NULL "
            "ORDER BY received_at LIMIT ?",
            (limit,),
        ).fetchall()
        return [json.loads(row["entry_json"]) for row in rows]

    def get_unbatched_entry_ids(self) -> list[str]:
        """Get entry_ids of entries not yet assigned to a batch.

        Returns:
            List of entry_id strings.
        """
        rows = self._conn.execute(
            "SELECT entry_id FROM entries WHERE batch_id IS NULL ORDER BY received_at",
        ).fetchall()
        return [row["entry_id"] for row in rows]

    def mark_entries_batched(self, entry_ids: list[str], batch_id: str) -> None:
        """Mark entries as belonging to a batch.

        Args:
            entry_ids: List of entry_id strings.
            batch_id: The batch they belong to.
        """
        for entry_id in entry_ids:
            self._conn.execute(
                "UPDATE entries SET batch_id = ? WHERE entry_id = ?",
                (batch_id, entry_id),
            )
        self._conn.commit()

    # ── Batches ─────────────────────────────────────────────────────────────

    def store_batch(self, batch_dict: dict[str, Any]) -> str:
        """Store a batch record.

        Args:
            batch_dict: The batch as a dict (from Batch.to_dict()).

        Returns:
            The batch_id.
        """
        batch_id = batch_dict["batch_id"]
        receipt = batch_dict.get("anchor_receipt")
        self._conn.execute(
            "INSERT INTO batches "
            "(batch_id, merkle_root, item_count, item_hashes_json, created_at, "
            "anchor_receipt_json, anchored_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                batch_id,
                batch_dict["merkle_root"],
                batch_dict["item_count"],
                json.dumps(batch_dict["item_hashes"]),
                batch_dict["timestamp"],
                json.dumps(receipt) if receipt else None,
                int(time.time()) if receipt else None,
            ),
        )
        self._conn.commit()
        return batch_id

    def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        """Get a batch by batch_id.

        Returns:
            The batch dict, or None if not found.
        """
        row = self._conn.execute(
            "SELECT * FROM batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_batch_dict(row)

    def get_latest_batch(self) -> dict[str, Any] | None:
        """Get the most recently created batch.

        Returns:
            The batch dict, or None if no batches exist.
        """
        row = self._conn.execute(
            "SELECT * FROM batches ORDER BY created_at DESC LIMIT 1",
        ).fetchone()
        if row is None:
            return None
        return self._row_to_batch_dict(row)

    def update_batch_anchor(self, batch_id: str, receipt_dict: dict[str, Any]) -> None:
        """Update a batch with an anchor receipt.

        Args:
            batch_id: The batch to update.
            receipt_dict: The anchor receipt dict.
        """
        self._conn.execute(
            "UPDATE batches SET anchor_receipt_json = ?, anchored_at = ? WHERE batch_id = ?",
            (json.dumps(receipt_dict), int(time.time()), batch_id),
        )
        self._conn.commit()

    def _row_to_batch_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a batch row to a Batch-compatible dict."""
        receipt_json = row["anchor_receipt_json"]
        return {
            "batch_id": row["batch_id"],
            "merkle_root": row["merkle_root"],
            "item_count": row["item_count"],
            "item_hashes": json.loads(row["item_hashes_json"]),
            "timestamp": row["created_at"],
            "anchor_receipt": json.loads(receipt_json) if receipt_json else None,
        }

    # ── Proofs ──────────────────────────────────────────────────────────────

    def store_proofs(self, proofs: list[dict[str, Any]]) -> None:
        """Store Merkle proofs.

        Each dict must have keys: entry_id, batch_id, proof (the proof dict).

        Args:
            proofs: List of proof records.
        """
        for p in proofs:
            self._conn.execute(
                "INSERT OR REPLACE INTO proofs (entry_id, batch_id, proof_json) "
                "VALUES (?, ?, ?)",
                (p["entry_id"], p["batch_id"],
                 json.dumps(p["proof"], sort_keys=True, separators=(",", ":"))),
            )
        self._conn.commit()

    def get_proof(self, entry_id: str) -> dict[str, Any] | None:
        """Get the Merkle proof for an entry.

        Returns:
            A dict with keys batch_id and proof, or None if not found.
        """
        row = self._conn.execute(
            "SELECT batch_id, proof_json FROM proofs WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "batch_id": row["batch_id"],
            "proof": json.loads(row["proof_json"]),
        }

    # ── Dashboard Queries ─────────────────────────────────────────────────────

    def get_all_certificates(self) -> list[dict[str, Any]]:
        """Get all registered certificates, newest first.

        Returns:
            List of certificate dicts.
        """
        rows = self._conn.execute(
            "SELECT certificate_json, registered_at FROM certificates "
            "ORDER BY registered_at DESC",
        ).fetchall()
        results = []
        for row in rows:
            cert = json.loads(row["certificate_json"])
            cert["_registered_at"] = row["registered_at"]
            results.append(cert)
        return results

    def get_recent_entries(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get the most recent entries across all agents.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of entry dicts, newest first.
        """
        rows = self._conn.execute(
            "SELECT entry_json, batch_id FROM entries "
            "ORDER BY received_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for row in rows:
            entry = json.loads(row["entry_json"])
            entry["_batch_id"] = row["batch_id"]
            results.append(entry)
        return results

    def get_recent_batches(self, limit: int = 5) -> list[dict[str, Any]]:
        """Get the most recent batches.

        Args:
            limit: Maximum number of batches to return.

        Returns:
            List of batch dicts, newest first.
        """
        rows = self._conn.execute(
            "SELECT * FROM batches ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_batch_dict(row) for row in rows]

    def get_entries_by_cert(
        self, cert_id: str, offset: int = 0, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Get entries for a specific certificate, newest first.

        Args:
            cert_id: The certificate ID.
            offset: Number of entries to skip.
            limit: Maximum number of entries to return.

        Returns:
            List of entry dicts with _batch_id attached.
        """
        rows = self._conn.execute(
            "SELECT entry_json, batch_id FROM entries "
            "WHERE cert_id = ? ORDER BY sequence DESC LIMIT ? OFFSET ?",
            (cert_id, limit, offset),
        ).fetchall()
        results = []
        for row in rows:
            entry = json.loads(row["entry_json"])
            entry["_batch_id"] = row["batch_id"]
            results.append(entry)
        return results

    def get_entry_count_by_cert(self, cert_id: str) -> int:
        """Get the number of entries for a specific certificate.

        Args:
            cert_id: The certificate ID.

        Returns:
            Entry count.
        """
        row = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
        return row[0]

    def get_entries_by_batch(self, batch_id: str) -> list[dict[str, Any]]:
        """Get all entries belonging to a batch.

        Args:
            batch_id: The batch ID.

        Returns:
            List of entry dicts.
        """
        rows = self._conn.execute(
            "SELECT entry_json FROM entries WHERE batch_id = ? ORDER BY sequence",
            (batch_id,),
        ).fetchall()
        return [json.loads(row["entry_json"]) for row in rows]

    def get_all_batches(self) -> list[dict[str, Any]]:
        """Get all batches, newest first.

        Returns:
            List of batch dicts.
        """
        rows = self._conn.execute(
            "SELECT * FROM batches ORDER BY created_at DESC",
        ).fetchall()
        return [self._row_to_batch_dict(row) for row in rows]

    def get_last_active_by_cert(self, cert_id: str) -> int | None:
        """Get the timestamp of the most recent entry for a certificate.

        Args:
            cert_id: The certificate ID.

        Returns:
            Unix timestamp, or None if no entries.
        """
        row = self._conn.execute(
            "SELECT MAX(received_at) FROM entries WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
        return row[0] if row and row[0] else None

    # ── Stats ───────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Get service statistics.

        Returns:
            Dict with counts and last anchor info.
        """
        entries_total = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        entries_pending = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE batch_id IS NULL"
        ).fetchone()[0]
        batches_total = self._conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
        certs_total = self._conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]

        last_anchor_row = self._conn.execute(
            "SELECT anchored_at FROM batches WHERE anchored_at IS NOT NULL "
            "ORDER BY anchored_at DESC LIMIT 1"
        ).fetchone()
        last_anchor = last_anchor_row[0] if last_anchor_row else None

        return {
            "certificates_total": certs_total,
            "entries_total": entries_total,
            "entries_pending": entries_pending,
            "batches_total": batches_total,
            "last_anchor": last_anchor,
        }

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
