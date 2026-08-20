"""
CAPTCHA-like password image generator.
Uses SVG rendering with no external dependencies.
"""

import base64
import math
import random

# Use a cryptographically secure RNG because CAPTCHA protects password display.
_rng = random.SystemRandom()


def generate_password_captcha(password: str, width: int = 280, height: int = 80) -> str:
    """
    Generate a CAPTCHA-style SVG image displaying the password.

    Args:
        password: Password to display.
        width: Image width.
        height: Image height.

    Returns:
        Base64-encoded SVG data URI.
    """
    # Character colors (high contrast on dark background)
    colors = ["#00d4ff", "#7b2cbf", "#4ade80", "#facc15", "#fb7185", "#f97316", "#a78bfa"]

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        # Background
        '<rect width="100%" height="100%" fill="#0d1117"/>',
    ]

    # Add random-line noise.
    for _ in range(8):
        x1 = _rng.randint(0, width)
        y1 = _rng.randint(0, height)
        x2 = _rng.randint(0, width)
        y2 = _rng.randint(0, height)
        color = _rng.choice(["#30363d", "#21262d", "#161b22"])
        stroke_width = _rng.uniform(1, 3)
        svg_parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{color}" stroke-width="{stroke_width}"/>'
        )

    # Add noise dots
    for _ in range(30):
        cx = _rng.randint(0, width)
        cy = _rng.randint(0, height)
        r = _rng.uniform(1, 3)
        color = _rng.choice(["#30363d", "#21262d", "#3d4450"])
        svg_parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}"/>')

    # Draw password characters
    char_width = (width - 40) / len(password)
    start_x = 20

    for i, char in enumerate(password):
        x = start_x + i * char_width + char_width / 2
        y = height / 2

        # Random distortion
        rotation = _rng.randint(-15, 15)
        y_offset = _rng.randint(-8, 8)
        font_size = _rng.randint(24, 32)
        color = _rng.choice(colors)

        # Small offset for each character
        x_offset = _rng.randint(-3, 3)

        svg_parts.append(
            f'<text x="{x + x_offset}" y="{y + y_offset + font_size / 3}" '
            f'font-family="Consolas, Monaco, monospace" '
            f'font-size="{font_size}" font-weight="bold" '
            f'fill="{color}" text-anchor="middle" '
            f'transform="rotate({rotation}, {x + x_offset}, {y + y_offset})">'
            f"{_escape_xml(char)}</text>"
        )

    # Add wavy lines on top of text
    for _ in range(3):
        points = []
        y_base = _rng.randint(20, height - 20)
        amplitude = _rng.randint(5, 15)
        frequency = _rng.uniform(0.02, 0.05)
        phase = _rng.uniform(0, 2 * math.pi)

        for x in range(0, width, 5):
            y = y_base + amplitude * math.sin(frequency * x + phase)
            points.append(f"{x},{y:.1f}")

        color = _rng.choice(["#30363d", "#21262d", "#2d333b"])
        svg_parts.append(
            f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2"/>'
        )

    svg_parts.append("</svg>")

    svg_content = "".join(svg_parts)

    # Encode to base64
    svg_b64 = base64.b64encode(svg_content.encode("utf-8")).decode("utf-8")

    return f"data:image/svg+xml;base64,{svg_b64}"


def _escape_xml(text: str) -> str:
    """Escape special XML characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
