"""lightning-trace/1 canonical trace model — Python side.

One schema, three brains (driver / cln / vls). This package is the
Python producer + consumer surface of the same JSONL envelope the Rust
side emits (``vls-core/src/trace``). The tables in :mod:`ptrace.schema`
MUST mirror ``EventPayload::trace_level``/``provenance`` in
``vls-core/src/trace/event.rs`` — a change there is a change here.

Design rules inherited from the schema doc (docs/splice-trace.md):

* provenance is assigned by payload type, never by the caller — an
  implementation cannot mislabel inference as observation;
* ``derived`` is consumer-only: no writer may emit it;
* levels (core/base/extra) filter heavyweight attachments (snapshots,
  raw artifacts) — CORE is small and CI-safe;
* no secret key material: the writer refuses secret-shaped payload
  keys outright (defense in depth on top of the Rust typed builders).
"""

__version__ = "0.1.0"

from .schema import (  # noqa: F401
    LEGACY_SCHEMA,
    LEVEL_NAMES,
    LEVELS,
    PAYLOAD_META,
    SCHEMA,
    TraceWriter,
    actor_rank,
    payload_meta,
    provenance_of,
)
