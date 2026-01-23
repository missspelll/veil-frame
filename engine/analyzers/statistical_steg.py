"""Statistical steganalysis using external tools (stegexpose and optional aletheia)."""

import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any

from .utils import MAX_PENDING_TIME, update_data


def analyze_statistical_steg(
    input_img: Path,
    output_dir: Path,
    deep_analysis: bool = False
) -> None:
    """Run statistical steganalysis using available tools."""
    if not deep_analysis:
        update_data(
            output_dir,
            {
                "statistical_steg": {
                    "status": "skipped",
                    "reason": "Enable deep analysis to run statistical steganalysis",
                }
            },
        )
        return

    try:
        results = {
            "aletheia": None,
            "stegexpose": None,
            "verdict": "unknown",
        }

        # Try aletheia first
        if shutil.which("aletheia"):
            results["aletheia"] = _run_aletheia(input_img, output_dir)

        # Try stegexpose
        if shutil.which("stegexpose"):
            results["stegexpose"] = _run_stegexpose(input_img, output_dir)

        # Determine verdict
        if results["aletheia"] or results["stegexpose"]:
            verdicts = []

            if results["aletheia"]:
                verdicts.append(results["aletheia"].get("verdict", "unknown"))

            if results["stegexpose"]:
                verdicts.append(results["stegexpose"].get("verdict", "unknown"))

            # If any tool detects stego, flag it
            if "stego_detected" in verdicts or "likely_stego" in verdicts:
                results["verdict"] = "likely_stego"
            elif "suspicious" in verdicts:
                results["verdict"] = "suspicious"
            else:
                results["verdict"] = "clean"
        else:
            results["verdict"] = "no_tools_available"
            results["note"] = "Install 'stegexpose' for statistical analysis"

        update_data(
            output_dir,
            {
                "statistical_steg": {
                    "status": "ok",
                    "output": results,
                    "summary": _format_summary(results),
                }
            },
        )
    except Exception as e:
        update_data(
            output_dir,
            {"statistical_steg": {"status": "error", "error": str(e)}},
        )


def _run_aletheia(input_img: Path, output_dir: Path) -> Dict[str, Any]:
    """Run aletheia steganalysis."""
    try:
        # Get file type
        img_format = input_img.suffix.lower()

        # Aletheia has different detectors for different formats
        if img_format in [".jpg", ".jpeg"]:
            detector = "structural-detector"
        else:
            detector = "spatial-detector"

        # Run aletheia
        cmd = ["aletheia", detector, str(input_img)]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_PENDING_TIME,
            check=False,
        )

        output = result.stdout + result.stderr

        # Parse output
        verdict = "unknown"
        confidence = 0.0

        # Aletheia outputs probabilities
        if "LSB replacement" in output or "Stego detected" in output:
            verdict = "stego_detected"
            confidence = 0.8
        elif "clean" in output.lower() or "no stego" in output.lower():
            verdict = "clean"
            confidence = 0.7

        return {
            "tool": "aletheia",
            "detector": detector,
            "verdict": verdict,
            "confidence": confidence,
            "raw_output": output[:500],  # Truncate
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "aletheia",
            "verdict": "timeout",
            "error": f"Timed out after {MAX_PENDING_TIME} seconds",
        }
    except Exception as e:
        return {
            "tool": "aletheia",
            "verdict": "error",
            "error": str(e),
        }


def _run_stegexpose(input_img: Path, output_dir: Path) -> Dict[str, Any]:
    """Run stegexpose steganalysis."""
    try:
        # stegexpose runs multiple tests: chi2, rs, spa
        cmd = ["stegexpose", str(input_img)]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAX_PENDING_TIME,
            check=False,
        )

        output = result.stdout + result.stderr

        # Parse output
        verdict = "unknown"
        tests_passed = 0
        tests_failed = 0

        # Check for test results
        if "chi-square" in output.lower():
            if "passed" in output.lower():
                tests_passed += 1
            elif "failed" in output.lower():
                tests_failed += 1

        if "rs analysis" in output.lower():
            if "passed" in output.lower():
                tests_passed += 1
            elif "failed" in output.lower():
                tests_failed += 1

        # Determine verdict
        if tests_failed > 0:
            verdict = "suspicious"
        elif tests_passed > 0:
            verdict = "clean"

        return {
            "tool": "stegexpose",
            "verdict": verdict,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "raw_output": output[:500],
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "stegexpose",
            "verdict": "timeout",
            "error": f"Timed out after {MAX_PENDING_TIME} seconds",
        }
    except Exception as e:
        return {
            "tool": "stegexpose",
            "verdict": "error",
            "error": str(e),
        }


def _format_summary(results: Dict[str, Any]) -> str:
    """Format summary of statistical analysis."""
    verdict = results.get("verdict", "unknown")

    if verdict == "likely_stego":
        return "Statistical analysis indicates likely steganography"
    elif verdict == "suspicious":
        return "Statistical tests show suspicious indicators"
    elif verdict == "clean":
        return "Statistical analysis shows no strong indicators"
    elif verdict == "no_tools_available":
        return "Statistical analysis tools not installed (install stegexpose)"
    else:
        return f"Statistical analysis: {verdict}"
