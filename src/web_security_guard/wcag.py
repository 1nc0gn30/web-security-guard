"""WCAG 2.2 Color Contrast Analyzer and Color Blindness Simulator.

Provides mathematically exact relative luminance calculation according to W3C WCAG 2.2,
contrast ratio evaluation for text and UI components across Level AA and AAA criteria,
and physiological Color Vision Deficiency (CVD) simulation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union

# Standard Named CSS Colors
_NAMED_COLORS: Dict[str, Tuple[int, int, int]] = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (255, 0, 0),
    "green": (0, 128, 0),
    "blue": (0, 0, 255),
    "yellow": (255, 255, 0),
    "cyan": (0, 255, 255),
    "magenta": (255, 0, 255),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "darkgray": (169, 169, 169),
    "darkgrey": (169, 169, 169),
    "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211),
    "orange": (255, 165, 0),
    "purple": (128, 0, 128),
    "navy": (0, 0, 128),
    "teal": (0, 128, 128),
    "silver": (192, 192, 192),
    "maroon": (128, 0, 0),
    "olive": (128, 128, 0),
    "lime": (0, 255, 0),
    "aqua": (0, 255, 255),
    "fuchsia": (255, 0, 255),
}

# Color Vision Deficiency (CVD) Linear RGB Transformation Matrices
_CVD_MATRICES: Dict[str, List[List[float]]] = {
    "protanopia": [
        [0.56667, 0.43333, 0.0],
        [0.55833, 0.44167, 0.0],
        [0.0, 0.24167, 0.75833],
    ],
    "deuteranopia": [
        [0.625, 0.375, 0.0],
        [0.70, 0.30, 0.0],
        [0.0, 0.30, 0.70],
    ],
    "tritanopia": [
        [0.95, 0.05, 0.0],
        [0.0, 0.43333, 0.56667],
        [0.0, 0.475, 0.525],
    ],
    "protanomaly": [
        [0.81667, 0.18333, 0.0],
        [0.33333, 0.66667, 0.0],
        [0.0, 0.125, 0.875],
    ],
    "deuteranomaly": [
        [0.80, 0.20, 0.0],
        [0.25833, 0.74167, 0.0],
        [0.0, 0.14167, 0.85833],
    ],
    "tritanomaly": [
        [0.96667, 0.03333, 0.0],
        [0.0, 0.73333, 0.26667],
        [0.0, 0.18333, 0.81667],
    ],
    "achromatopsia": [
        [0.2126, 0.7152, 0.0722],
        [0.2126, 0.7152, 0.0722],
        [0.2126, 0.7152, 0.0722],
    ],
    "monochromacy": [
        [0.2126, 0.7152, 0.0722],
        [0.2126, 0.7152, 0.0722],
        [0.2126, 0.7152, 0.0722],
    ],
    "achromatomaly": [
        [0.618, 0.320, 0.062],
        [0.163, 0.775, 0.062],
        [0.163, 0.320, 0.516],
    ],
}


def parse_color(color: Union[str, Tuple[int, int, int], List[int]]) -> Tuple[int, int, int]:
    """Parse various color formats into an (R, G, B) integer tuple with values 0-255.

    Supports:
    - 3-digit hex: '#fff', 'fff'
    - 4-digit hex: '#ffff', 'ffff'
    - 6-digit hex: '#ffffff', 'ffffff'
    - 8-digit hex: '#ffffffff', 'ffffffff'
    - CSS rgb() / rgba(): 'rgb(255, 255, 255)', 'rgba(0, 0, 0, 0.5)'
    - Named CSS colors: 'white', 'black', 'navy', etc.
    - Tuple/List: (255, 255, 255), [0, 0, 0]

    Returns:
        (R, G, B) integer tuple where 0 <= R, G, B <= 255.

    Raises:
        ValueError: If color format is unrecognized.
    """
    if isinstance(color, (tuple, list)):
        if len(color) < 3:
            raise ValueError(f"Color tuple must have at least 3 components, got {color}")
        r, g, b = int(color[0]), int(color[1]), int(color[2])
        return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))

    if not isinstance(color, str):
        raise ValueError(f"Unsupported color type: {type(color)}")

    raw = color.strip().lower()

    # Named color lookup
    if raw in _NAMED_COLORS:
        return _NAMED_COLORS[raw]

    # rgb(...) / rgba(...) syntax
    rgb_match = re.match(r"^rgba?\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", raw)
    if rgb_match:
        r, g, b = int(rgb_match.group(1)), int(rgb_match.group(2)), int(rgb_match.group(3))
        return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))

    # Hex syntax
    clean_hex = raw.lstrip("#")
    if len(clean_hex) == 3:  # #RGB -> #RRGGBB
        r = int(clean_hex[0] * 2, 16)
        g = int(clean_hex[1] * 2, 16)
        b = int(clean_hex[2] * 2, 16)
        return (r, g, b)
    elif len(clean_hex) == 4:  # #RGBA -> #RRGGBB
        r = int(clean_hex[0] * 2, 16)
        g = int(clean_hex[1] * 2, 16)
        b = int(clean_hex[2] * 2, 16)
        return (r, g, b)
    elif len(clean_hex) == 6:  # #RRGGBB
        r = int(clean_hex[0:2], 16)
        g = int(clean_hex[2:4], 16)
        b = int(clean_hex[4:6], 16)
        return (r, g, b)
    elif len(clean_hex) == 8:  # #RRGGBBAA
        r = int(clean_hex[0:2], 16)
        g = int(clean_hex[2:4], 16)
        b = int(clean_hex[4:6], 16)
        return (r, g, b)

    raise ValueError(f"Invalid color representation: '{color}'")


def format_hex_color(rgb: Tuple[int, int, int]) -> str:
    """Format (R, G, B) integer tuple as a lowercase #rrggbb string."""
    r, g, b = rgb
    return f"#{r:02x}{g:02x}{b:02x}"


def calculate_relative_luminance(rgb: Union[Tuple[int, int, int], List[int], str]) -> float:
    """Calculate the relative luminance of a color according to W3C WCAG 2.2 formula.

    L = 0.2126 * R + 0.7152 * G + 0.0722 * B
    where each linearized channel C is:
      C / 12.92                        if (C / 255.0) <= 0.04045
      ((C / 255.0 + 0.055) / 1.055)^2.4 otherwise

    Args:
        rgb: Color specification as (R, G, B) tuple, list, or hex string.

    Returns:
        Relative luminance float in the range [0.0, 1.0].
    """
    r_int, g_int, b_int = parse_color(rgb)

    def _linearize(channel_255: int) -> float:
        s = channel_255 / 255.0
        if s <= 0.04045:
            return s / 12.92
        return ((s + 0.055) / 1.055) ** 2.4

    r_lin = _linearize(r_int)
    g_lin = _linearize(g_int)
    b_lin = _linearize(b_int)

    return 0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin


def calculate_contrast_ratio(
    color_a: Union[str, Tuple[int, int, int], List[int]],
    color_b: Union[str, Tuple[int, int, int], List[int]],
    round_digits: Optional[int] = 2,
) -> float:
    """Calculate the contrast ratio between two colors according to WCAG 2.2.

    Formula: (L1 + 0.05) / (L2 + 0.05)
    where L1 is the relative luminance of the lighter color, and L2 is the darker color.

    Args:
        color_a: First color (hex string, named color, or RGB tuple).
        color_b: Second color (hex string, named color, or RGB tuple).
        round_digits: Optional decimal places to round result to (default: 2).

    Returns:
        Contrast ratio between 1.0 and 21.0.
    """
    lum_a = calculate_relative_luminance(color_a)
    lum_b = calculate_relative_luminance(color_b)

    lighter = max(lum_a, lum_b)
    darker = min(lum_a, lum_b)

    ratio = (lighter + 0.05) / (darker + 0.05)

    if round_digits is not None:
        return round(ratio, round_digits)
    return ratio


def evaluate_wcag_contrast(
    fg_color: Union[str, Tuple[int, int, int], List[int]],
    bg_color: Union[str, Tuple[int, int, int], List[int]],
    font_size_pt: float = 12.0,
    bold: bool = False,
) -> Dict[str, Any]:
    """Evaluate foreground and background color combination against WCAG 2.2 contrast criteria.

    Criteria:
    - Normal Text (< 18pt regular or < 14pt bold): Level AA requires >= 4.5:1, AAA requires >= 7.0:1.
    - Large Text (>= 18pt regular or >= 14pt bold): Level AA requires >= 3.0:1, AAA requires >= 4.5:1.
    - UI Components & Graphical Objects (WCAG 2.1/2.2 Criterion 1.4.11): requires >= 3.0:1.

    Args:
        fg_color: Text or foreground color.
        bg_color: Background color.
        font_size_pt: Font size in typographical points (pt).
        bold: Whether font weight is bold (>= 700 or font-weight: bold).

    Returns:
        Comprehensive compliance dictionary with pass/fail flags, ratio, and recommendations.
    """
    fg_rgb = parse_color(fg_color)
    bg_rgb = parse_color(bg_color)

    fg_hex = format_hex_color(fg_rgb)
    bg_hex = format_hex_color(bg_rgb)

    fg_lum = calculate_relative_luminance(fg_rgb)
    bg_lum = calculate_relative_luminance(bg_rgb)

    ratio = calculate_contrast_ratio(fg_rgb, bg_rgb, round_digits=2)

    # Large text definition: 18pt+ or 14pt+ bold
    is_large_text = (font_size_pt >= 18.0) or (font_size_pt >= 14.0 and bold)

    # Compliance flags
    aa_normal = ratio >= 4.5
    aa_large = ratio >= 3.0
    aaa_normal = ratio >= 7.0
    aaa_large = ratio >= 4.5
    ui_component = ratio >= 3.0

    # Specific scenario compliance
    passes_aa = aa_large if is_large_text else aa_normal
    passes_aaa = aaa_large if is_large_text else aaa_normal

    if passes_aaa:
        wcag_level = "AAA"
        rec = "Excellent contrast. Meets WCAG 2.2 AAA standard for all text sizes."
    elif passes_aa:
        wcag_level = "AA"
        rec = "Good contrast. Meets WCAG 2.2 AA standard for the specified typography."
    elif ui_component:
        wcag_level = "UI_ONLY"
        rec = "Sufficient for UI components and large text, but fails WCAG 2.2 AA for body text."
    else:
        wcag_level = "FAIL"
        rec = "Insufficient contrast. Fails WCAG 2.2 accessibility standards. Increase lightness difference."

    return {
        "fg_color": fg_hex,
        "bg_color": bg_hex,
        "contrast_ratio": ratio,
        "formatted_ratio": f"{ratio:.2f}:1",
        "font_size_pt": font_size_pt,
        "bold": bold,
        "is_large_text": is_large_text,
        "aa_normal_text": aa_normal,
        "aa_large_text": aa_large,
        "aaa_normal_text": aaa_normal,
        "aaa_large_text": aaa_large,
        "ui_component_pass": ui_component,
        "passes_aa": passes_aa,
        "passes_aaa": passes_aaa,
        "fg_luminance": round(fg_lum, 4),
        "bg_luminance": round(bg_lum, 4),
        "wcag_level": wcag_level,
        "recommendation": rec,
    }


def simulate_color_blindness(
    hex_color: Union[str, Tuple[int, int, int]],
    kind: str = "protanopia",
) -> str:
    """Simulate human color vision deficiency (color blindness) for a given color.

    Transforms color through linear sRGB space via standard physiological CVD projection matrices.

    Args:
        hex_color: Source color string (hex, named, or rgb tuple).
        kind: CVD type:
            - 'protanopia' (L-cone red deficient)
            - 'deuteranopia' (M-cone green deficient)
            - 'tritanopia' (S-cone blue deficient)
            - 'protanomaly' (anomalous red trichromacy)
            - 'deuteranomaly' (anomalous green trichromacy)
            - 'tritanomaly' (anomalous blue trichromacy)
            - 'achromatopsia' or 'monochromacy' (total color blindness)
            - 'achromatomaly' (partial monochromacy)

    Returns:
        Simulated color as lowercase '#rrggbb' hex string.

    Raises:
        ValueError: If unsupported CVD kind is provided.
    """
    kind_norm = kind.lower().strip()
    if kind_norm not in _CVD_MATRICES:
        supported = ", ".join(sorted(_CVD_MATRICES.keys()))
        raise ValueError(f"Unsupported color blindness type '{kind}'. Supported: {supported}")

    r_int, g_int, b_int = parse_color(hex_color)

    # 1. Convert sRGB [0..255] to linear RGB [0..1]
    def srgb_to_lin(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4

    r_lin = srgb_to_lin(r_int)
    g_lin = srgb_to_lin(g_int)
    b_lin = srgb_to_lin(b_int)

    # 2. Apply 3x3 CVD Transformation Matrix
    mat = _CVD_MATRICES[kind_norm]
    r_sim_lin = mat[0][0] * r_lin + mat[0][1] * g_lin + mat[0][2] * b_lin
    g_sim_lin = mat[1][0] * r_lin + mat[1][1] * g_lin + mat[1][2] * b_lin
    b_sim_lin = mat[2][0] * r_lin + mat[2][1] * g_lin + mat[2][2] * b_lin

    # 3. Convert linear RGB back to gamma-corrected sRGB [0..255]
    def lin_to_srgb(c_lin: float) -> int:
        clamped = max(0.0, min(1.0, c_lin))
        if clamped <= 0.0031308:
            s = 12.92 * clamped
        else:
            s = 1.055 * (clamped ** (1.0 / 2.4)) - 0.055
        val = round(s * 255.0)
        return max(0, min(255, val))

    r_out = lin_to_srgb(r_sim_lin)
    g_out = lin_to_srgb(g_sim_lin)
    b_out = lin_to_srgb(b_sim_lin)

    return format_hex_color((r_out, g_out, b_out))
