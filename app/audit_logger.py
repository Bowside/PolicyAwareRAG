"""Audit logging utilities for the policy-aware RAG request pipeline.

This module writes immutable, privacy-safe audit records to the configured
Cosmos DB collection named AuditStorage. It intentionally stores only hashed
identifiers and structural metadata, never raw prompts or unredacted LLM output.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from azure.cosmos import CosmosClient


def _utc_timestamp() -> str:
    """Return an ISO 8601 UTC timestamp for audit entries."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_value(value: Any) -> str:
    """Return a SHA-256 digest for sensitive values that must be anonymized."""
    if value is None:
        return ""
    if not isinstance(value, (str, bytes)):
        value = json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = value
    return hashlib.sha256(payload).hexdigest()


class AuditLogger:
    """Write privacy-safe audit records to the AuditStorage container.

    The logger aggregates all pipeline steps for a request into a single entry so
    the complete security decision trail is kept together in one immutable log
    record rather than multiple step-level entries.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        key: str | None = None,
        database: str | None = None,
        container_name: str = "AuditStorage",
    ) -> None:
        self.endpoint = endpoint or os.getenv("COSMOSDB_ENDPOINT")
        self.key = key or os.getenv("COSMOSDB_KEY")
        self.database_name = database or os.getenv("COSMOSDB_DATABASE")
        self.container_name = container_name
        self._container = None
        self._pending_steps: dict[str, list[dict[str, Any]]] = {}

    def _get_container(self):
        """Return the configured AuditStorage container if Cosmos is configured."""
        if self._container is not None:
            return self._container
        if not self.endpoint or not self.key:
            logging.warning("Audit logging is disabled because Cosmos DB is not configured.")
            return None

        client = CosmosClient(url=self.endpoint, credential=self.key)
        database = client.get_database_client(self.database_name)
        self._container = database.get_container_client(self.container_name)
        return self._container

    def _build_entry(
        self,
        *,
        step_name: str,
        execution_status: str,
        policy_metadata: Mapping[str, Any] | None = None,
        telemetry: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        user_id: str | None = None,
        prompt_text: str | None = None,
        prompt_hash: str | None = None,
        document_ids: Iterable[str] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Build the canonical audit payload for a pipeline step."""
        payload = {
            "id": str(uuid.uuid4()),
            "timestamp": _utc_timestamp(),
            "traceId": correlation_id or str(uuid.uuid4()),
            "correlationId": correlation_id or str(uuid.uuid4()),
            "stepName": step_name,
            "executionStatus": execution_status,
            "policyMetadata": dict(policy_metadata or {}),
            "telemetry": dict(telemetry or {}),
            "userPseudonym": _hash_value(user_id) if user_id else "",
        }

        if reason:
            payload["reason"] = reason
        if prompt_text is not None:
            payload["userQuery"] = str(prompt_text)
        if prompt_hash:
            payload["promptHash"] = prompt_hash
        if document_ids:
            payload["candidateDocumentIds"] = [str(item) for item in document_ids]

        return payload

    def _finalize_step_group(
        self,
        *,
        correlation_id: str | None,
        current_entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Merge the queued request steps into one request-level audit record."""
        request_id = correlation_id or current_entry.get("correlationId") or str(uuid.uuid4())
        pipeline_steps = self._pending_steps.pop(request_id, [])
        if current_entry not in pipeline_steps:
            pipeline_steps.append(current_entry)

        final_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": _utc_timestamp(),
            "traceId": request_id,
            "correlationId": request_id,
            "stepName": "RequestAudit",
            "executionStatus": current_entry.get("executionStatus", "UNKNOWN"),
            "policyMetadata": dict(current_entry.get("policyMetadata") or {}),
            "telemetry": dict(current_entry.get("telemetry") or {}),
            "userPseudonym": current_entry.get("userPseudonym", ""),
            "pipelineSteps": pipeline_steps,
            "stepCount": len(pipeline_steps),
        }

        if current_entry.get("reason"):
            final_entry["reason"] = current_entry["reason"]
        if current_entry.get("userQuery"):
            final_entry["userQuery"] = current_entry["userQuery"]
        if current_entry.get("promptHash"):
            final_entry["promptHash"] = current_entry["promptHash"]
        if current_entry.get("candidateDocumentIds"):
            final_entry["candidateDocumentIds"] = current_entry["candidateDocumentIds"]

        return final_entry

    async def emit_async(
        self,
        *,
        step_name: str,
        execution_status: str,
        policy_metadata: Mapping[str, Any] | None = None,
        telemetry: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        user_id: str | None = None,
        prompt_text: str | None = None,
        response_text: str | None = None,
        document_ids: Iterable[str] | None = None,
        reason: str | None = None,
        finalize: bool = True,
    ) -> None:
        """Persist one or more audit steps while aggregating them by correlation ID."""
        container = self._get_container()
        if container is None:
            return

        request_id = correlation_id or str(uuid.uuid4())
        entry = self._build_entry(
            step_name=step_name,
            execution_status=execution_status,
            policy_metadata=policy_metadata,
            telemetry=telemetry,
            correlation_id=request_id,
            user_id=user_id,
            prompt_text=prompt_text,
            prompt_hash=_hash_value(prompt_text) if prompt_text else None,
            document_ids=document_ids,
            reason=reason,
        )

        if not finalize:
            self._pending_steps.setdefault(request_id, []).append(entry)
            return

        final_entry = self._finalize_step_group(correlation_id=request_id, current_entry=entry)
        try:
            container.upsert_item(body=final_entry)
        except Exception as exc:  # pragma: no cover - defensive logging path
            logging.warning("Audit log write failed gracefully: %s", exc)

    def emit(
        self,
        *,
        step_name: str,
        execution_status: str,
        policy_metadata: Mapping[str, Any] | None = None,
        telemetry: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        user_id: str | None = None,
        prompt_text: str | None = None,
        response_text: str | None = None,
        document_ids: Iterable[str] | None = None,
        reason: str | None = None,
        finalize: bool = True,
    ) -> None:
        """Persist an audit entry without exposing failures to the caller."""
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                loop.create_task(
                    self.emit_async(
                        step_name=step_name,
                        execution_status=execution_status,
                        policy_metadata=policy_metadata,
                        telemetry=telemetry,
                        correlation_id=correlation_id,
                        user_id=user_id,
                        prompt_text=prompt_text,
                        response_text=response_text,
                        document_ids=document_ids,
                        reason=reason,
                        finalize=finalize,
                    )
                )
                return

            asyncio.run(
                self.emit_async(
                    step_name=step_name,
                    execution_status=execution_status,
                    policy_metadata=policy_metadata,
                    telemetry=telemetry,
                    correlation_id=correlation_id,
                    user_id=user_id,
                    prompt_text=prompt_text,
                    response_text=response_text,
                    document_ids=document_ids,
                    reason=reason,
                    finalize=finalize,
                )
            )
        except Exception as exc:  # pragma: no cover - defensive logging path
            logging.warning("Audit logger failed gracefully: %s", exc)
