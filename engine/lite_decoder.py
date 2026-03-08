"""Minimal decoder pipeline used by veil-frame-lite."""

from __future__ import annotations

import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict

from .analyzers import analyze_advanced_lsb, analyze_simple_lsb, analyze_simple_zlib
from .lsb_planes import extract_plane_payloads, plane_payload_results


def _read_results_file(output_dir: Path) -> Dict[str, Any]:
    results_path = output_dir / "results.json"
    if not results_path.exists():
        return {}
    with open(results_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_lite_analysis(image_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Run the lightweight decoder stack for quick LSB workflows."""
    if not isinstance(image_bytes, bytes):
        raise TypeError(f"image_bytes must be bytes, got {type(image_bytes).__name__}")
    if not image_bytes:
        raise ValueError("Cannot analyze empty image data")

    safe_name = Path(filename or "upload.png").name
    started = time.perf_counter()

    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        image_path = tmp_dir / safe_name
        output_dir = tmp_dir / "analysis"
        output_dir.mkdir(parents=True, exist_ok=True)

        image_path.write_bytes(image_bytes)

        try:
            simple_rgb, channels = extract_plane_payloads(image_path)
        except Exception as exc:
            print(f"Warning: Failed to decode plane payloads: {exc}")
            simple_rgb = ""
            channels = {
                "red_plane": "",
                "green_plane": "",
                "blue_plane": "",
                "alpha_plane": "",
            }
        planes = plane_payload_results(simple_rgb, channels)

        analyze_simple_lsb(image_path, output_dir)
        analyze_simple_zlib(image_path, output_dir)
        analyze_advanced_lsb(image_path, output_dir)

        results = {**planes, **_read_results_file(output_dir)}
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "results": results,
            "artifacts": {"images": [], "archives": []},
            "meta": {
                "profile": "lite",
                "profile_label": "Lite",
                "eta_label": "5s - 45s",
                "elapsed_ms": elapsed_ms,
            },
        }
