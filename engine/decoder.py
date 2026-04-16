"""Wrapper to run the analyzer suite on an uploaded image."""

from __future__ import annotations

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Set, Tuple

from PIL import Image

from .analyzer_catalog import ANALYZER_CATALOG, normalize_selected_tools
from .analysis_profiles import resolve_profile
from .analyzers import (
    analyze_advanced_lsb,
    analyze_audio_echo,
    analyze_audio_fft,
    analyze_audio_lsb,
    analyze_audio_spectrogram,
    analyze_binwalk,
    analyze_channel_cipher,
    analyze_decomposer,
    analyze_entropy_anomalies,
    analyze_exiftool,
    analyze_foremost,
    analyze_homoglyph,
    analyze_invisible_unicode,
    analyze_invisible_unicode_decode,
    analyze_jpeg_qtables,
    analyze_matryoshka,
    analyze_outguess,
    analyze_payload_unwrap,
    analyze_plane_carver,
    analyze_pre_scan,
    analyze_randomizer_decode,
    analyze_simple_lsb,
    analyze_simple_zlib,
    analyze_statistical_steg,
    analyze_stegg,
    analyze_steghide,
    analyze_strings,
    analyze_tool_suite,
    analyze_whitespace_steg,
    analyze_xor_flag_sweep,
    analyze_zero_width,
    analyze_zsteg,
)
from .analyzers.utils import update_data
from .decode_registry import get_registry
from .lsb_planes import extract_plane_payloads, plane_payload_results
from .option_decoders import build_auto_detect_result
from .tooling import get_tool_status


def _sniff_image_mime(path: Path) -> str:
    """Best-effort MIME sniffing for auto ranking and profile display."""
    try:
        data = path.read_bytes()[:16]
    except Exception:
        data = b""

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"

    try:
        img = Image.open(path)
        if img.format:
            return "image/" + img.format.lower()
    except Exception:
        pass

    return ""


def _file_to_data_url(path: Path, mime: str) -> str:
    """Read a file and convert to data URL."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    try:
        data = path.read_bytes()
    except Exception as exc:
        raise IOError(f"Failed to read file '{path}': {str(exc)}")

    try:
        b64 = base64.b64encode(data).decode()
        return f"data:{mime};base64,{b64}"
    except Exception as exc:
        raise ValueError(f"Failed to encode file as base64 data URL: {str(exc)}")


def _read_results_file(output_dir: Path) -> Dict[str, Any]:
    """Load results.json if present."""
    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    results_path = output_dir / "results.json"
    if not results_path.exists():
        return {}

    try:
        with open(results_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse results.json: {str(exc)}")
    except Exception as exc:
        raise IOError(f"Failed to read results.json: {str(exc)}")


def _collect_artifacts(output_dir: Path) -> Dict[str, List[Dict[str, str]]]:
    """Collect generated artifacts as base64 data URLs."""
    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    images: List[Dict[str, str]] = []
    archives: List[Dict[str, str]] = []

    try:
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file():
                continue

            try:
                suffix = path.suffix.lower()
                if suffix in {".png", ".jpg", ".jpeg"}:
                    mime = "image/png" if suffix == ".png" else "image/jpeg"
                    images.append({"name": path.name, "data_url": _file_to_data_url(path, mime)})
                elif suffix == ".7z":
                    archives.append(
                        {
                            "name": path.name,
                            "data_url": _file_to_data_url(
                                path,
                                "application/x-7z-compressed",
                            ),
                        }
                    )
            except Exception as exc:
                print(f"Warning: Failed to process artifact file '{path}': {str(exc)}")

        return {"images": images, "archives": archives}
    except Exception as exc:
        raise IOError(f"Failed to collect artifacts from {output_dir}: {str(exc)}")


def _build_option_result(
    option: Dict[str, Any],
    *,
    status: str,
    summary: str,
    confidence: float = 0.0,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "option_id": option["id"],
        "label": option["label"],
        "status": status,
        "confidence": round(float(confidence), 3),
        "summary": summary,
        "details": details or {},
        "artifacts": [],
        "timing_ms": 0,
        "mode": option.get("mode", "auto"),
    }


def _run_decode_options(
    image_path: Path,
    output_dir: Path,
    *,
    password: Optional[str],
    deep_analysis: bool,
    spread_enabled: bool,
    input_mime: str,
) -> Dict[str, Dict[str, Any]]:
    registry = get_registry()
    option_results: Dict[str, Dict[str, Any]] = {}

    for option_id, option in registry.items():
        if option_id == "auto_detect":
            continue

        mode = option.get("mode", "auto")
        if option_id == "spread_spectrum" and not spread_enabled:
            result = _build_option_result(
                option,
                status="skipped",
                summary="Enable spread spectrum to run password-based decoding.",
            )
            update_data(output_dir, {option_id: result})
            option_results[option_id] = result
            continue

        if mode == "deep" and not deep_analysis:
            result = _build_option_result(
                option,
                status="skipped",
                summary="Profile depth is not deep enough for this decoder.",
            )
            update_data(output_dir, {option_id: result})
            option_results[option_id] = result
            continue

        params = {"password": password}
        try:
            result = option["analyzer"](image_path, **option["params"](option, params))
        except Exception as exc:
            result = {
                "option_id": option_id,
                "label": option.get("label", option_id),
                "status": "error",
                "confidence": 0.0,
                "summary": f"Decoder failed: {exc}",
                "details": {},
                "artifacts": [],
                "timing_ms": 0,
            }
        result["mode"] = mode
        update_data(output_dir, {option_id: result})
        option_results[option_id] = result

    auto_option = registry.get("auto_detect")
    if auto_option:
        auto_result = build_auto_detect_result(
            auto_option["id"],
            auto_option["label"],
            option_results,
            input_mime=input_mime,
        )
        auto_result["mode"] = auto_option.get("mode", "auto")
        update_data(output_dir, {"auto_detect": auto_result})
        option_results["auto_detect"] = auto_result

    return option_results


def _mark_profile_skips(output_dir: Path, *, profile_label: str) -> None:
    update_data(
        output_dir,
        {
            "binwalk": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "foremost": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "exiftool": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "strings": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "steghide": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "zsteg": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "tool_suite": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "decomposer": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "stegg": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "zero_width": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "entropy_analyzer": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "jpeg_qtable_analyzer": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "statistical_steg": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "homoglyph": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "whitespace_steg": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "audio_lsb": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "audio_fft": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "audio_echo": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "audio_spectrogram": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "matryoshka": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
            "channel_cipher": {
                "status": "skipped",
                "reason": f"Skipped in {profile_label} profile.",
            },
        },
    )


def _mark_deselected_skips(
    output_dir: Path,
    analyzer_ids: Set[str],
    *,
    reason: str = "disabled by custom tool selection",
) -> None:
    if not analyzer_ids:
        return
    payload = {
        analyzer_id: {
            "status": "skipped",
            "reason": reason,
        }
        for analyzer_id in sorted(analyzer_ids)
    }
    update_data(output_dir, payload)


def _build_analyzer_plan(
    image_path: Path,
    output_dir: Path,
    *,
    profile,
    password: Optional[str],
    binwalk_extract: bool,
    invisible_unicode: bool,
    unicode_tier1: bool,
    unicode_separators: bool,
    unicode_aggressiveness: str,
    selected_tools: Optional[Set[str]],
) -> List[Tuple[str, Any, Tuple[Any, ...], Dict[str, Any]]]:
    """Compose analyzer tasks from profile selection."""
    plan: List[Tuple[str, Any, Tuple[Any, ...], Dict[str, Any]]] = [
        ("pre_analysis", analyze_pre_scan, (image_path, output_dir), {}),
        ("advanced_lsb", analyze_advanced_lsb, (image_path, output_dir), {}),
        ("simple_lsb", analyze_simple_lsb, (image_path, output_dir), {}),
        ("simple_zlib", analyze_simple_zlib, (image_path, output_dir), {}),
        ("randomizer_decode", analyze_randomizer_decode, (image_path, output_dir), {}),
        (
            "payload_unwrap",
            analyze_payload_unwrap,
            (image_path, output_dir),
            {"deep_analysis": profile.run_decode_deep},
        ),
        (
            "xor_flag_sweep",
            analyze_xor_flag_sweep,
            (image_path, output_dir),
            {"deep_analysis": profile.run_decode_deep},
        ),
    ]

    if profile.run_external_basic:
        plan.extend(
            [
                ("binwalk", analyze_binwalk, (image_path, output_dir, binwalk_extract), {}),
                ("decomposer", analyze_decomposer, (image_path, output_dir), {}),
                ("exiftool", analyze_exiftool, (image_path, output_dir), {}),
                ("foremost", analyze_foremost, (image_path, output_dir), {}),
                ("stegg", analyze_stegg, (image_path, output_dir), {}),
                ("zero_width", analyze_zero_width, (image_path, output_dir), {}),
                ("strings", analyze_strings, (image_path, output_dir), {}),
                ("steghide", analyze_steghide, (image_path, output_dir, password), {}),
                ("zsteg", analyze_zsteg, (image_path, output_dir), {}),
                ("entropy_analyzer", analyze_entropy_anomalies, (image_path, output_dir), {}),
                (
                    "jpeg_qtable_analyzer",
                    analyze_jpeg_qtables,
                    (image_path, output_dir),
                    {},
                ),
                (
                    "statistical_steg",
                    analyze_statistical_steg,
                    (image_path, output_dir, profile.run_decode_deep),
                    {},
                ),
                ("homoglyph", analyze_homoglyph, (image_path, output_dir), {}),
                ("whitespace_steg", analyze_whitespace_steg, (image_path, output_dir), {}),
                ("audio_lsb", analyze_audio_lsb, (image_path, output_dir), {}),
                ("audio_spectrogram", analyze_audio_spectrogram, (image_path, output_dir), {}),
            ]
        )
        if profile.run_decode_deep:
            plan.extend(
                [
                    ("audio_fft", analyze_audio_fft, (image_path, output_dir), {}),
                    ("audio_echo", analyze_audio_echo, (image_path, output_dir), {}),
                    ("matryoshka", analyze_matryoshka, (image_path, output_dir), {}),
                    ("channel_cipher", analyze_channel_cipher, (image_path, output_dir), {}),
                ]
            )
        else:
            update_data(
                output_dir,
                {
                    "audio_fft": {
                        "status": "skipped",
                        "reason": f"Disabled in {profile.label} profile.",
                    },
                    "audio_echo": {
                        "status": "skipped",
                        "reason": f"Disabled in {profile.label} profile.",
                    },
                    "matryoshka": {
                        "status": "skipped",
                        "reason": f"Disabled in {profile.label} profile.",
                    },
                    "channel_cipher": {
                        "status": "skipped",
                        "reason": f"Disabled in {profile.label} profile.",
                    },
                },
            )
        if profile.run_tool_suite:
            plan.append(
                (
                    "tool_suite",
                    analyze_tool_suite,
                    (
                        image_path,
                        output_dir,
                        profile.run_decode_deep,
                        profile.run_manual_tools,
                    ),
                    {},
                )
            )
        else:
            update_data(
                output_dir,
                {
                    "tool_suite": {
                        "status": "skipped",
                        "reason": f"Disabled in {profile.label} profile.",
                    }
                },
            )
    else:
        _mark_profile_skips(output_dir, profile_label=profile.label)

    if profile.run_plane_carver:
        plan.append(("plane_carver", analyze_plane_carver, (image_path, output_dir), {}))
    else:
        update_data(
            output_dir,
            {
                "plane_carver": {
                    "status": "skipped",
                    "reason": f"Disabled in {profile.label} profile.",
                }
            },
        )

    if profile.run_outguess:
        try:
            tools = get_tool_status()
            if tools.get("outguess", {}).get("available"):
                plan.append(("outguess", analyze_outguess, (image_path, output_dir, password), {}))
            else:
                update_data(
                    output_dir,
                    {
                        "outguess": {
                            "status": "skipped",
                            "reason": "outguess not installed in runtime environment",
                        }
                    },
                )
        except Exception as exc:
            print(f"Warning: Failed to check outguess availability: {str(exc)}")
    else:
        update_data(
            output_dir,
            {
                "outguess": {
                    "status": "skipped",
                    "reason": f"Disabled in {profile.label} profile.",
                }
            },
        )

    plan.append(
        (
            "invisible_unicode",
            analyze_invisible_unicode,
            (image_path, output_dir, invisible_unicode),
            {
                "tier1": unicode_tier1,
                "separators": unicode_separators,
                "aggressiveness": unicode_aggressiveness,
            },
        )
    )
    plan.append(
        (
            "invisible_unicode_decode",
            analyze_invisible_unicode_decode,
            (image_path, output_dir, invisible_unicode),
            {
                "aggressiveness": unicode_aggressiveness,
            },
        )
    )

    if selected_tools is None:
        return plan

    selected_plan: List[Tuple[str, Any, Tuple[Any, ...], Dict[str, Any]]] = []
    deselected_ids: Set[str] = set()
    for task in plan:
        analyzer_id = task[0]
        if analyzer_id in selected_tools:
            selected_plan.append(task)
        else:
            deselected_ids.add(analyzer_id)

    _mark_deselected_skips(output_dir, deselected_ids)
    return selected_plan


def run_analysis(
    image_bytes: bytes,
    filename: str,
    *,
    password: Optional[str] = None,
    deep_analysis: bool = False,
    manual_tools: bool = False,
    binwalk_extract: bool = False,
    invisible_unicode: bool = False,
    unicode_tier1: bool = False,
    unicode_separators: bool = False,
    unicode_aggressiveness: str = "balanced",
    decode_option: Optional[str] = None,
    spread_enabled: bool = False,
    analysis_profile: Optional[str] = None,
    selected_tools: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Execute analyzer stack over uploaded image bytes."""
    if not isinstance(image_bytes, bytes):
        raise TypeError(f"image_bytes must be bytes, got {type(image_bytes).__name__}")
    if not image_bytes:
        raise ValueError("Cannot analyze empty image data")

    if not filename:
        filename = "upload.png"

    try:
        safe_name = Path(filename).name or "upload.png"
    except Exception as exc:
        raise ValueError(f"Invalid filename: {str(exc)}")

    profile = resolve_profile(
        analysis_profile,
        deep_analysis=deep_analysis,
        manual_tools=manual_tools,
    )
    selected_tool_set = normalize_selected_tools(selected_tools)

    started_all = time.perf_counter()

    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        image_path = tmp_dir / safe_name
        output_dir = tmp_dir / "analysis"
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(image_path, "wb") as handle:
            handle.write(image_bytes)

        input_mime = _sniff_image_mime(image_path)

        if decode_option:
            registry = get_registry()
            option = registry.get(decode_option)
            if not option:
                raise ValueError(f"Unknown decode option '{decode_option}'")

            if decode_option == "auto_detect":
                result = option["analyzer"](
                    image_path,
                    option_id=option["id"],
                    label=option["label"],
                    registry=registry,
                    password=password,
                )
            else:
                params = {"password": password}
                result = option["analyzer"](image_path, **option["params"](option, params))

            update_data(output_dir, {decode_option: result})

            if invisible_unicode:
                analyze_invisible_unicode(
                    image_path,
                    output_dir,
                    invisible_unicode,
                    tier1=unicode_tier1,
                    separators=unicode_separators,
                    aggressiveness=unicode_aggressiveness,
                )
                analyze_invisible_unicode_decode(
                    image_path,
                    output_dir,
                    invisible_unicode,
                    aggressiveness=unicode_aggressiveness,
                )

            elapsed_ms = int((time.perf_counter() - started_all) * 1000)
            return {
                "results": _read_results_file(output_dir),
                "artifacts": _collect_artifacts(output_dir),
                "meta": {
                    "profile": profile.profile_id,
                    "profile_label": profile.label,
                    "eta_label": profile.eta_label,
                    "elapsed_ms": elapsed_ms,
                    "input_mime": input_mime,
                    "single_option": decode_option,
                },
            }

        try:
            simple_rgb_text, channel_texts = extract_plane_payloads(image_path)
        except Exception as exc:
            print(f"Warning: Failed to decode plane payloads: {str(exc)}")
            simple_rgb_text = ""
            channel_texts = {
                "red_plane": "",
                "green_plane": "",
                "blue_plane": "",
                "alpha_plane": "",
            }

        plane_results = plane_payload_results(simple_rgb_text, channel_texts)
        update_data(output_dir, plane_results)

        _run_decode_options(
            image_path,
            output_dir,
            password=password,
            deep_analysis=profile.run_decode_deep,
            spread_enabled=spread_enabled,
            input_mime=input_mime,
        )

        plan = _build_analyzer_plan(
            image_path,
            output_dir,
            profile=profile,
            password=password,
            binwalk_extract=binwalk_extract,
            invisible_unicode=invisible_unicode,
            unicode_tier1=unicode_tier1,
            unicode_separators=unicode_separators,
            unicode_aggressiveness=unicode_aggressiveness,
            selected_tools=selected_tool_set,
        )

        analyzer_timing: Dict[str, Dict[str, Any]] = {}

        def run_task(
            task: Tuple[str, Any, Tuple[Any, ...], Dict[str, Any]]
        ) -> Tuple[str, bool, int]:
            name, analyzer_func, args, kwargs = task
            task_started = time.perf_counter()
            try:
                analyzer_func(*args, **kwargs)
                elapsed = int((time.perf_counter() - task_started) * 1000)
                return name, True, elapsed
            except Exception as exc:  # pragma: no cover - defensive
                print(f"Analyzer {name} failed: {exc}")
                elapsed = int((time.perf_counter() - task_started) * 1000)
                return name, False, elapsed

        max_workers = max(1, min(8, len(plan)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(run_task, task): task for task in plan}
            for future in as_completed(futures):
                try:
                    name, success, elapsed = future.result(timeout=300)
                    analyzer_timing[name] = {
                        "status": "ok" if success else "error",
                        "timing_ms": elapsed,
                    }
                except Exception as exc:
                    task_name = futures[future][0]
                    print(f"Task {task_name} raised unexpected exception: {exc}")
                    analyzer_timing[task_name] = {
                        "status": "error",
                        "timing_ms": 0,
                    }

        try:
            results = _read_results_file(output_dir)
        except Exception as exc:
            print(f"Warning: Failed to read results file: {str(exc)}")
            results = {}

        results = {**plane_results, **results}

        try:
            artifacts = _collect_artifacts(output_dir)
        except Exception as exc:
            print(f"Warning: Failed to collect artifacts: {str(exc)}")
            artifacts = {"images": [], "archives": []}

        elapsed_ms = int((time.perf_counter() - started_all) * 1000)
        available_tools = [task[0] for task in plan]
        selected_meta = (
            sorted(selected_tool_set)
            if selected_tool_set is not None
            else sorted(available_tools)
        )
        selected_labels = [
            ANALYZER_CATALOG[item].label
            for item in selected_meta
            if item in ANALYZER_CATALOG
        ]
        return {
            "results": results,
            "artifacts": artifacts,
            "meta": {
                "profile": profile.profile_id,
                "profile_label": profile.label,
                "eta_label": profile.eta_label,
                "elapsed_ms": elapsed_ms,
                "input_mime": input_mime,
                "analyzer_timing": analyzer_timing,
                "selected_tools": selected_meta,
                "selected_tool_labels": selected_labels,
            },
        }
