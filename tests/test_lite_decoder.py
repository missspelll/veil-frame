from pathlib import Path

from engine.lite_decoder import run_lite_analysis


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_lite_decoder_returns_core_plane_and_lsb_results():
    image_path = FIXTURES / "lsb.png"
    result = run_lite_analysis(image_path.read_bytes(), image_path.name)

    assert result["meta"]["profile"] == "lite"
    for key in (
        "simple_rgb",
        "red_plane",
        "green_plane",
        "blue_plane",
        "alpha_plane",
        "simple_lsb",
        "simple_zlib",
        "advanced_lsb",
    ):
        assert key in result["results"]
