"""Tests for CAPTCHA-style password image generator."""

import base64

from xferry.utils.captcha import _escape_xml, generate_password_captcha


class TestGeneratePasswordCaptcha:
    """Test SVG CAPTCHA generation."""

    def test_returns_data_uri(self):
        result = generate_password_captcha("secret")
        assert result.startswith("data:image/svg+xml;base64,")

    def test_svg_contains_valid_xml(self):
        result = generate_password_captcha("test")
        svg_b64 = result.split(",", 1)[1]
        svg = base64.b64decode(svg_b64).decode("utf-8")
        assert svg.startswith("<svg")
        assert svg.endswith("</svg>")

    def test_svg_contains_password_chars(self):
        password = "abc"
        result = generate_password_captcha(password)
        svg = base64.b64decode(result.split(",", 1)[1]).decode("utf-8")
        for char in password:
            assert char in svg

    def test_single_character(self):
        result = generate_password_captcha("X")
        svg = base64.b64decode(result.split(",", 1)[1]).decode("utf-8")
        assert ">X</text>" in svg

    def test_long_password(self):
        result = generate_password_captcha("A" * 50)
        assert result.startswith("data:image/svg+xml;base64,")

    def test_special_characters_escaped(self):
        result = generate_password_captcha('<>&"')
        svg = base64.b64decode(result.split(",", 1)[1]).decode("utf-8")
        # Raw < and > should not appear outside of tags
        assert "&lt;" in svg
        assert "&gt;" in svg
        assert "&amp;" in svg

    def test_custom_dimensions(self):
        result = generate_password_captcha("pw", width=400, height=120)
        svg = base64.b64decode(result.split(",", 1)[1]).decode("utf-8")
        assert 'width="400"' in svg
        assert 'height="120"' in svg

    def test_svg_has_noise_elements(self):
        result = generate_password_captcha("test")
        svg = base64.b64decode(result.split(",", 1)[1]).decode("utf-8")
        assert "<line" in svg
        assert "<circle" in svg
        assert "<polyline" in svg

    def test_different_calls_produce_different_output(self):
        """Randomized distortion means two calls differ."""
        r1 = generate_password_captcha("same")
        r2 = generate_password_captcha("same")
        # With SystemRandom distortion, outputs should differ
        assert r1 != r2


class TestEscapeXml:
    """Test XML character escaping."""

    def test_ampersand(self):
        assert _escape_xml("a&b") == "a&amp;b"

    def test_less_than(self):
        assert _escape_xml("a<b") == "a&lt;b"

    def test_greater_than(self):
        assert _escape_xml("a>b") == "a&gt;b"

    def test_double_quote(self):
        assert _escape_xml('a"b') == "a&quot;b"

    def test_single_quote(self):
        assert _escape_xml("a'b") == "a&#39;b"

    def test_no_special_chars(self):
        assert _escape_xml("hello") == "hello"

    def test_all_special_chars(self):
        assert _escape_xml("<&>\"'") == "&lt;&amp;&gt;&quot;&#39;"

    def test_empty_string(self):
        assert _escape_xml("") == ""
