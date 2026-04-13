"""
One-shot helper: hide a text payload inside an image using the same
simple_lsb path the web app uses (compress-to-~900KB, then write LSBs
across the RGB plane). PNG output so the LSBs survive.

Usage:
    python scripts/encode_simple_lsb.py <input_image> <output_image> "<text>"

Example:
    python scripts/encode_simple_lsb.py map.jpg map_encoded.png "ytuqa://wajcpsl.zy/omktkpVGt"
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make `engine` importable when run as `python scripts/encode_simple_lsb.py ...`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.encoder import encode_payload


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    text = sys.argv[3]

    image_bytes = in_path.read_bytes()
    _, encoded = encode_payload(
        image_bytes,
        filename=in_path.name,
        mode="text",
        plane="RGB",
        text=text,
        output_format="png",
        lossy_output=False,
    )
    out_path.write_bytes(encoded)
    print(f"wrote {out_path} ({len(encoded)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
