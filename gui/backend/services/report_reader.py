"""Load the most recent JSON report produced for a given scan."""
from __future__ import annotations

import glob
import json
import logging
import os
from typing import Any, Dict, Optional


log = logging.getLogger("hunterpy.api.report_reader")


def latest_report_for(rec) -> Optional[Dict[str, Any]]:
    """Find the newest *.json report for the scan's target on disk.

    HunterPy writes reports with the pattern
    `<target>_<YYYYMMDD>_<HHMMSS>.json`. We pick the most recent matching
    file because the engine timestamps by run, not by scan_id.
    """
    output_dir = (rec.options.get("output_dir") if rec.options else None) \
                 or "./output"
    if not os.path.isdir(output_dir):
        return None

    # Slugify target the same way ReportEngine does.
    slug = rec.target.replace("://", "_").replace("/", "_").replace(":", "_")
    pattern = os.path.join(output_dir, f"{slug}_*.json")
    matches = sorted(glob.glob(pattern))
    if not matches:
        return None
    path = matches[-1]
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        log.warning("could not read %s: %s", path, e)
        return None
