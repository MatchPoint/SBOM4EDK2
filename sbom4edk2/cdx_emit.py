"""Write CycloneDX JSON documents to disk."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def emit_cdx_json(doc: dict[str, Any], output_path: str) -> int:
    """Serialize *doc* to *output_path* (indented UTF-8 JSON). Returns 0 on success."""
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        return 0
    except OSError as exc:
        logger.error("Failed to write %s: %s", output_path, exc)
        return 1
