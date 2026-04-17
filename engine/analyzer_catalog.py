"""Analyzer catalog metadata for UI tool selection and ETA hints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class AnalyzerSpec:
    analyzer_id: str
    label: str
    description: str
    eta_seconds: int
    profiles: tuple[str, ...]
    kind: str

    @property
    def eta_label(self) -> str:
        sec = max(1, int(self.eta_seconds))
        if sec < 60:
            return f"~{sec}s"
        minutes, rem = divmod(sec, 60)
        if rem == 0:
            return f"~{minutes}m"
        return f"~{minutes}m {rem}s"


ANALYZER_CATALOG: Dict[str, AnalyzerSpec] = {
    "plane_payloads": AnalyzerSpec(
        analyzer_id="plane_payloads",
        label="plane payloads",
        description="simple rgb + per-channel plane text extraction",
        eta_seconds=10,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "option_decoders": AnalyzerSpec(
        analyzer_id="option_decoders",
        label="format decoders",
        description="auto-detect sweep across lsb/pvd/dct/f5/palette/chroma/png chunks",
        eta_seconds=25,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "pre_analysis": AnalyzerSpec(
        analyzer_id="pre_analysis",
        label="smart pre-scan",
        description="quick entropy + format triage to prioritize likely payload paths",
        eta_seconds=20,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "advanced_lsb": AnalyzerSpec(
        analyzer_id="advanced_lsb",
        label="advanced lsb",
        description="per-channel text/zlib detector for multi-plane payloads",
        eta_seconds=35,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "simple_lsb": AnalyzerSpec(
        analyzer_id="simple_lsb",
        label="simple lsb",
        description="common lsb text extraction across rgb/rgba planes",
        eta_seconds=30,
        profiles=("simple", "quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "simple_zlib": AnalyzerSpec(
        analyzer_id="simple_zlib",
        label="simple zlib",
        description="zlib stream recovery from typical lsb bitstreams",
        eta_seconds=35,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "randomizer_decode": AnalyzerSpec(
        analyzer_id="randomizer_decode",
        label="randomizer decode",
        description="shuffle/xor candidate decodes for obfuscated plaintext",
        eta_seconds=45,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "payload_unwrap": AnalyzerSpec(
        analyzer_id="payload_unwrap",
        label="payload unwrap",
        description="unwrap base64/base91/xor/rot payload wrappers",
        eta_seconds=75,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "xor_flag_sweep": AnalyzerSpec(
        analyzer_id="xor_flag_sweep",
        label="xor flag sweep",
        description="keyword-guided xor sweep for ctf-style payloads",
        eta_seconds=90,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "binwalk": AnalyzerSpec(
        analyzer_id="binwalk",
        label="binwalk",
        description="signature scan for embedded file segments",
        eta_seconds=80,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "decomposer": AnalyzerSpec(
        analyzer_id="decomposer",
        label="bit-plane decomposer",
        description="render per-plane images for visual payload inspection",
        eta_seconds=70,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "exiftool": AnalyzerSpec(
        analyzer_id="exiftool",
        label="exiftool",
        description="metadata and profile anomaly extraction",
        eta_seconds=20,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "foremost": AnalyzerSpec(
        analyzer_id="foremost",
        label="foremost",
        description="header/footer carving for hidden file recovery",
        eta_seconds=120,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "stegg": AnalyzerSpec(
        analyzer_id="stegg",
        label="stegg",
        description="legacy stegg-compatible decode probe",
        eta_seconds=55,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "zero_width": AnalyzerSpec(
        analyzer_id="zero_width",
        label="zero-width",
        description="zero-width unicode hidden text extraction",
        eta_seconds=25,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "strings": AnalyzerSpec(
        analyzer_id="strings",
        label="strings",
        description="readable byte sequences from carrier file",
        eta_seconds=20,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "steghide": AnalyzerSpec(
        analyzer_id="steghide",
        label="steghide",
        description="steghide extraction using provided password",
        eta_seconds=45,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "zsteg": AnalyzerSpec(
        analyzer_id="zsteg",
        label="zsteg",
        description="png/bmp lsb brute and signature extraction",
        eta_seconds=90,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "entropy_analyzer": AnalyzerSpec(
        analyzer_id="entropy_analyzer",
        label="entropy analyzer",
        description="channel entropy anomalies and lsb randomness checks",
        eta_seconds=35,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "jpeg_qtable_analyzer": AnalyzerSpec(
        analyzer_id="jpeg_qtable_analyzer",
        label="jpeg qtable analyzer",
        description="jpeg quantization table forensic hints",
        eta_seconds=40,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "statistical_steg": AnalyzerSpec(
        analyzer_id="statistical_steg",
        label="statistical steg",
        description="statistical detection heuristics for embedded data",
        eta_seconds=65,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "tool_suite": AnalyzerSpec(
        analyzer_id="tool_suite",
        label="extended tool suite",
        description="broad external tool sweep for deep workshop analysis",
        eta_seconds=300,
        profiles=("balanced", "deep", "forensic"),
        kind="external",
    ),
    "plane_carver": AnalyzerSpec(
        analyzer_id="plane_carver",
        label="plane carver",
        description="file signature carving over many bitstream traversals",
        eta_seconds=220,
        profiles=("deep", "forensic"),
        kind="internal",
    ),
    "outguess": AnalyzerSpec(
        analyzer_id="outguess",
        label="outguess",
        description="outguess extraction pass with password",
        eta_seconds=160,
        profiles=("deep", "forensic"),
        kind="external",
    ),
    "invisible_unicode": AnalyzerSpec(
        analyzer_id="invisible_unicode",
        label="invisible unicode",
        description="raw unicode marker sweep across bytes and decoded text",
        eta_seconds=120,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    "invisible_unicode_decode": AnalyzerSpec(
        analyzer_id="invisible_unicode_decode",
        label="invisible unicode decode",
        description="decode pass for candidate invisible-unicode payloads",
        eta_seconds=80,
        profiles=("quick", "balanced", "deep", "forensic"),
        kind="internal",
    ),
    # --- ste.gg parity decoders ---
    "homoglyph": AnalyzerSpec(
        analyzer_id="homoglyph",
        label="homoglyph substitution",
        description="detect unicode lookalike characters encoding hidden bits",
        eta_seconds=30,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "whitespace_steg": AnalyzerSpec(
        analyzer_id="whitespace_steg",
        label="whitespace encoding",
        description="recover data from trailing spaces and tabs in text lines",
        eta_seconds=20,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "audio_lsb": AnalyzerSpec(
        analyzer_id="audio_lsb",
        label="audio lsb",
        description="extract hidden bits from audio sample lsbs",
        eta_seconds=45,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "audio_fft": AnalyzerSpec(
        analyzer_id="audio_fft",
        label="audio fft",
        description="frequency-domain signal extraction from audio spectrum",
        eta_seconds=60,
        profiles=("deep", "forensic"),
        kind="internal",
    ),
    "audio_echo": AnalyzerSpec(
        analyzer_id="audio_echo",
        label="echo hiding",
        description="detect echo-delay patterns encoding hidden bits in audio",
        eta_seconds=90,
        profiles=("deep", "forensic"),
        kind="internal",
    ),
    "audio_spectrogram": AnalyzerSpec(
        analyzer_id="audio_spectrogram",
        label="spectrogram art",
        description="render audio spectrogram for visual inspection of hidden images",
        eta_seconds=30,
        profiles=("balanced", "deep", "forensic"),
        kind="internal",
    ),
    "matryoshka": AnalyzerSpec(
        analyzer_id="matryoshka",
        label="matryoshka (nested)",
        description="recursive multi-layer extraction of embedded images",
        eta_seconds=300,
        profiles=("deep", "forensic"),
        kind="internal",
    ),
    "channel_cipher": AnalyzerSpec(
        analyzer_id="channel_cipher",
        label="channel cipher",
        description="password-seeded channel hopping extraction (godmode)",
        eta_seconds=120,
        profiles=("deep", "forensic"),
        kind="internal",
    ),
}


def list_analyzer_catalog(profile_id: Optional[str] = None) -> List[Dict[str, object]]:
    profile = (profile_id or "").strip().lower()
    rows: List[Dict[str, object]] = []
    for analyzer_id in sorted(ANALYZER_CATALOG.keys()):
        spec = ANALYZER_CATALOG[analyzer_id]
        enabled = True if not profile else profile in spec.profiles
        rows.append(
            {
                "id": spec.analyzer_id,
                "label": spec.label,
                "description": spec.description,
                "eta_seconds": spec.eta_seconds,
                "eta_label": spec.eta_label,
                "kind": spec.kind,
                "profiles": list(spec.profiles),
                "enabled_in_profile": enabled,
            }
        )
    return rows


def default_selected_for_profile(profile_id: Optional[str]) -> List[str]:
    profile = (profile_id or "simple").strip().lower() or "simple"
    selected: List[str] = []
    for spec in ANALYZER_CATALOG.values():
        if profile in spec.profiles:
            selected.append(spec.analyzer_id)
    return sorted(selected)


def normalize_selected_tools(raw_tools: Optional[List[str]]) -> Optional[Set[str]]:
    if raw_tools is None:
        return None

    normalized = {
        str(tool).strip().lower()
        for tool in raw_tools
        if str(tool).strip().lower() in ANALYZER_CATALOG
    }
    return normalized
