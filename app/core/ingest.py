"""Orchestration Phase 1 : fichier brut → parse → SQLite."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.normalizer import normalize_and_insert
from app.core.parsers import detect_scan_format, parse_scan_file


def ingest_scan_file(path: str, session: Session) -> dict[str, int]:
    fmt = detect_scan_format(path)
    parsed = parse_scan_file(path)
    return normalize_and_insert(parsed, session, scan_source=fmt)
