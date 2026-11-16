#!/usr/bin/env python3
"""atomicio.py -- one tiny shared helper: atomic file writes for the Redstrike ledgers.

A ledger (coverage / surface / re-convergence) is written and re-written as the hunt progresses and is
re-run idempotently by (possibly parallel) agents. A plain `Path.write_text` truncates the file first
and then writes; if that is interrupted (crash / kill / full disk) it leaves a half-written, invalid
JSON ledger behind, which the downstream gates then read. `atomic_write` writes to a temp file in the
SAME directory and `os.replace()`s it into place — an atomic rename on the same filesystem — so a reader
only ever sees the old complete file or the new complete file, never a torn one.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path, data: str, encoding: str = "utf-8") -> None:
    """Atomically write `data` to `path`: a temp file in the same directory + `os.replace`.

    The parent directory is created if missing. On any failure the temp file is cleaned up and the
    error re-raised, so a failed write never leaves a stray `.tmp` nor a corrupted target."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(p))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
