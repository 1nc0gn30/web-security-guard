"""Unit tests for web_security_guard.wcag module."""

from __future__ import annotations

import pytest

from web_security_guard.wcag import (
    calculate_contrast_ratio,
    calculate_relative_luminance,
    evaluate_wcag_contrast,
    format_hex_color,
    parse_color,
    simulate_color_blindness,
)


def test_parse_color() -> None:
    # 3-digit hex
    assert parse_color("#fff") == (255, 255, 255)
    assert parse_color("000") == (0, 0, 0)
    assert parse_color("#f0a") == (255, 0, 170)

    # 4-digit hex
    assert parse_color("#fff8") == (255, 255, 255)

    # 6-digit hex
    assert parse_color("#112233") == (17, 34, 51)
    assert parse_color("ffffff") == (255, 255, 255)

    # 8-digit hex
    assert parse_color("#112233aa") == (17, 34, 51)

    # rgb / rgba
    assert parse_color("rgb(10, 20, 30)") == (10, 20, 30)
    assert parse_color("rgba(100, 150, 200, 0.8)") == (100, 150, 200)

    # Named CSS colors
    assert parse_color("black") == (0, 0, 0)
    assert parse_color("white") == (255, 255, 255)
    assert parse_color("navy") == (0, 0, 128)

    # Tuple / List
    assert parse_color((12, 34, 56)) == (12, 34, 56)
    assert parse_color([200, 100, 50]) == (200, 100, 50)

    # Invalid
    with pytest.raises(ValueError, match="Invalid color representation"):
        parse_color("invalid_color_xyz")
    with pytest.raises(ValueError, match="Color tuple must have at least 3"):
        parse_color([10, 20])


def test_format_hex_color() -> None:
    assert format_hex_color((255, 255, 255)) == "#ffffff"
    assert format_hex_color((0, 0, 0)) == "#000000"
    assert format_hex_color((16, 32, 48)) == "#102030"


def test_calculate_relative_luminance() -> None:
    # Black is exactly 0.0
    assert calculate_relative_luminance("#000000") == 0.0
    # White is exactly 1.0
    assert pytest.approx(calculate_relative_luminance("#ffffff"), abs=1e-5) == 1.0

    # sRGB channel weights test: Green has highest weight (0.7152), Blue lowest (0.0722)
    lum_red = calculate_relative_luminance("#ff0000")
    lum_green = calculate_relative_luminance("#00ff00")
    lum_blue = calculate_relative_luminance("#0000ff")

    assert lum_green > lum_red > lum_blue
    assert pytest.approx(lum_red, abs=1e-3) == 0.2126
    assert pytest.approx(lum_green, abs=1e-3) == 0.7152
    assert pytest.approx(lum_blue, abs=1e-3) == 0.0722


def test_calculate_contrast_ratio() -> None:
    # Black on White is 21.0:1
    assert calculate_contrast_ratio("#000000", "#ffffff") == 21.0
    assert calculate_contrast_ratio("white", "black") == 21.0

    # Same color is 1.0:1
    assert calculate_contrast_ratio("#ffffff", "#ffffff") == 1.0
    assert calculate_contrast_ratio("#123456", "#123456") == 1.0

    # Blue (#0000ff) on White (#ffffff)
    blue_white = calculate_contrast_ratio("#0000ff", "#ffffff")
    assert pytest.approx(blue_white, abs=0.1) == 8.59


def test_evaluate_wcag_contrast() -> None:
    # 1. High contrast Black on White (passes AAA)
    res_high = evaluate_wcag_contrast("#000000", "#ffffff", font_size_pt=12.0)
    assert res_high["contrast_ratio"] == 21.0
    assert res_high["passes_aa"] is True
    assert res_high["passes_aaa"] is True
    assert res_high["ui_component_pass"] is True
    assert res_high["wcag_level"] == "AAA"

    # 2. Low contrast (fails all)
    res_fail = evaluate_wcag_contrast("#777777", "#666666", font_size_pt=12.0)
    assert res_fail["contrast_ratio"] < 3.0
    assert res_fail["passes_aa"] is False
    assert res_fail["passes_aaa"] is False
    assert res_fail["ui_component_pass"] is False
    assert res_fail["wcag_level"] == "FAIL"

    # 3. Large text vs normal text threshold
    # Ratio ~ 3.5:1 passes AA for large text (>=18pt or >=14pt bold), but fails for normal text (12pt regular)
    # #595959 on #ffffff has ratio ~ 7.0
    # Let's test a color with ratio between 3.0 and 4.5: e.g. #767676 on #ffffff has ratio ~ 4.54, #888888 on #ffffff is ~ 3.54
    res_normal = evaluate_wcag_contrast("#888888", "#ffffff", font_size_pt=12.0, bold=False)
    assert res_normal["is_large_text"] is False
    assert res_normal["passes_aa"] is False  # requires >= 4.5
    assert res_normal["ui_component_pass"] is True  # requires >= 3.0

    res_large = evaluate_wcag_contrast("#888888", "#ffffff", font_size_pt=18.0, bold=False)
    assert res_large["is_large_text"] is True
    assert res_large["passes_aa"] is True  # large text requires >= 3.0

    res_bold = evaluate_wcag_contrast("#888888", "#ffffff", font_size_pt=14.0, bold=True)
    assert res_bold["is_large_text"] is True
    assert res_bold["passes_aa"] is True


def test_simulate_color_blindness() -> None:
    # Test valid CVD modes
    modes = [
        "protanopia",
        "deuteranopia",
        "tritanopia",
        "protanomaly",
        "deuteranomaly",
        "tritanomaly",
        "achromatopsia",
        "monochromacy",
        "achromatomaly",
    ]
    test_color = "#ff3366"
    for mode in modes:
        sim = simulate_color_blindness(test_color, kind=mode)
        assert sim.startswith("#")
        assert len(sim) == 7

    # Pure black and pure white invariance
    assert simulate_color_blindness("#000000", kind="protanopia") == "#000000"
    assert simulate_color_blindness("#ffffff", kind="protanopia") == "#ffffff"
    assert simulate_color_blindness("#000000", kind="achromatopsia") == "#000000"
    assert simulate_color_blindness("#ffffff", kind="achromatopsia") == "#ffffff"

    # Red color in protanopia has significantly reduced red luminance
    red_sim = simulate_color_blindness("#ff0000", kind="protanopia")
    r, g, b = parse_color(red_sim)
    assert r < 255

    # Unsupported kind
    with pytest.raises(ValueError, match="Unsupported color blindness type"):
        simulate_color_blindness("#123456", kind="non_existent_cvd")
