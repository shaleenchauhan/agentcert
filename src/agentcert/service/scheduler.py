"""Background scheduler for batching and anchoring audit entries.

Runs as an asyncio background task inside the FastAPI app. On each cycle it
collects unbatched entries, builds a Merkle tree, stores proofs, and optionally
anchors the root to Bitcoin.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from agentcert.batch import create_batch, anchor_batch as _anchor_batch
from agentcert.merkle import MerkleTree
from agentcert.types import Batch, KeyPair, MerkleProof

from agentcert.service.config import ServiceConfig
from agentcert.service.models import Database

logger = logging.getLogger("agentcert.service.scheduler")


class BatchScheduler:
    """Background scheduler that batches entries and anchors to Bitcoin.

    Args:
        db: The service database.
        config: Service configuration.
    """

    def __init__(self, db: Database, config: ServiceConfig) -> None:
        self._db = db
        self._config = config
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._wallet_keys: KeyPair | None = None

        if config.anchor_wallet_key:
            from agentcert.keys import load_keys
            self._wallet_keys = load_keys(config.anchor_wallet_key)

    async def start(self) -> None:
        """Start the background batching loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "Batch scheduler started (interval=%ds, min_entries=%d)",
            self._config.batch_interval_seconds,
            self._config.batch_min_entries,
        )

    async def stop(self) -> None:
        """Stop the background loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Batch scheduler stopped")

    async def _loop(self) -> None:
        """Run the batching loop on a timer."""
        while self._running:
            await asyncio.sleep(self._config.batch_interval_seconds)
            try:
                await self.run_batch_cycle()
            except Exception:
                logger.exception("Error in batch cycle")

    async def run_batch_cycle(self) -> Batch | None:
        """Run one batch cycle.

        Collects unbatched entries, builds a Merkle tree, stores proofs,
        and optionally anchors. Thread-safe: the synchronous DB and batch
        operations run in the default executor.

        Returns:
            The batch if created, None if not enough entries.
        """
        return await asyncio.to_thread(self._run_batch_cycle_sync)

    async def force_batch(self) -> Batch | None:
        """Force a batch cycle immediately.

        Returns:
            The batch if created, None if no entries.
        """
        return await asyncio.to_thread(self._run_batch_cycle_sync)

    def _run_batch_cycle_sync(self) -> Batch | None:
        """Synchronous implementation of batch cycle."""
        unbatched = self._db.get_unbatched_entries(
            limit=self._config.batch_max_entries
        )

        if len(unbatched) < self._config.batch_min_entries:
            logger.debug(
                "Not enough entries to batch (%d < %d)",
                len(unbatched), self._config.batch_min_entries,
            )
            return None

        # Collect entry_ids as leaf hashes
        entry_ids = [e["entry_id"] for e in unbatched]

        # Build Merkle tree and batch
        batch, tree = create_batch(entry_ids)

        # Store the batch record
        self._db.store_batch(batch.to_dict())

        # Generate and store proofs
        proof_records: list[dict[str, Any]] = []
        for i, entry_id in enumerate(entry_ids):
            proof = tree.get_proof(i)
            proof_records.append({
                "entry_id": entry_id,
                "batch_id": batch.batch_id,
                "proof": proof.to_dict(),
            })
        self._db.store_proofs(proof_records)

        # Mark entries as batched
        self._db.mark_entries_batched(entry_ids, batch.batch_id)

        logger.info(
            "Batch created: %s (%d entries, root=%s)",
            batch.batch_id[:16], len(entry_ids), batch.merkle_root[:16],
        )

        # Anchor if wallet keys are configured
        if self._wallet_keys:
            try:
                anchored = _anchor_batch(
                    batch,
                    creator_keys=self._wallet_keys,
                    network=self._config.network,
                )
                self._db.update_batch_anchor(
                    batch.batch_id, anchored.anchor_receipt.to_dict()
                )
                logger.info(
                    "Batch anchored: txid=%s", anchored.anchor_receipt.txid[:16]
                )
                return anchored
            except Exception:
                logger.exception("Failed to anchor batch %s", batch.batch_id[:16])

        return batch
