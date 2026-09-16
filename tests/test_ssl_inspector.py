"""
Unit tests for SSL Inspector Module (web_security_guard.ssl_inspector).
"""

import datetime
from unittest.mock import MagicMock, patch
import pytest

from web_security_guard.ssl_inspector import (
    TLSGrade,
    extract_hostname_and_port,
    parse_cert_date,
    extract_rdn_dict,
    calculate_tls_grade,
    get_mock_tls_inspection,
    inspect_tls_and_cert,
    format_tls_markdown_report,
)


class TestHostnameAndPortExtraction:
    def test_https_url(self):
        host, port = extract_hostname_and_port("https://example.com")
        assert host == "example.com"
        assert port == 443

    def test_https_custom_port_url(self):
        host, port = extract_hostname_and_port("https://secure.example.org:8443/api/v1?token=xyz")
        assert host == "secure.example.org"
        assert port == 8443

    def test_http_url(self):
        host, port = extract_hostname_and_port("http://insecure.test/index.html")
        assert host == "insecure.test"
        assert port == 80

    def test_raw_hostname(self):
        host, port = extract_hostname_and_port("api.service.io")
        assert host == "api.service.io"
        assert port == 443

    def test_hostname_with_port(self):
        host, port = extract_hostname_and_port("localhost:9443")
        assert host == "localhost"
        assert port == 9443

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            extract_hostname_and_port("")


class TestCertDateParser:
    def test_openssl_standard_date(self):
        dt = parse_cert_date("May  1 12:00:00 2025 GMT")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 5
        assert dt.day == 1
        assert dt.hour == 12

    def test_openssl_two_digit_day(self):
        dt = parse_cert_date("Dec 25 18:30:00 2026 GMT")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 12
        assert dt.day == 25

    def test_iso_date(self):
        dt = parse_cert_date("2025-06-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 15

    def test_invalid_date(self):
        assert parse_cert_date("Not a date") is None
        assert parse_cert_date(None) is None


class TestRDNExtraction:
    def test_extract_rdn_nested_tuples(self):
        rdn_data = (
            (("commonName", "example.com"),),
            (("organizationName", "Example Inc"),),
            (("countryName", "US"),),
        )
        parsed = extract_rdn_dict(rdn_data)
        assert parsed["commonName"] == "example.com"
        assert parsed["organizationName"] == "Example Inc"
        assert parsed["countryName"] == "US"

    def test_empty_rdn(self):
        assert extract_rdn_dict(None) == {}
        assert extract_rdn_dict(()) == {}


class TestTLSGradeCalculation:
    def test_grade_a_plus_tls13(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            days_remaining=90,
            is_expired=False,
            is_trusted=True,
        )
        assert grade == TLSGrade.A_PLUS
        assert score == 100
        assert len(findings) == 0

    def test_grade_a_tls12(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.2",
            cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
            cipher_bits=128,
            days_remaining=60,
            is_expired=False,
            is_trusted=True,
        )
        assert grade == TLSGrade.A
        assert score == 90
        assert len(findings) == 0

    def test_grade_b_expiring_soon(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.2",
            cipher_name="ECDHE-RSA-AES256-GCM-SHA384",
            cipher_bits=256,
            days_remaining=20,
            is_expired=False,
            is_trusted=True,
        )
        assert grade == TLSGrade.B
        assert score == 75
        assert any(f["id"] == "TLS_CERT_EXPIRING_SOON" for f in findings)

    def test_grade_c_deprecated_tls11(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.1",
            cipher_name="ECDHE-RSA-AES128-SHA",
            cipher_bits=128,
            days_remaining=60,
            is_expired=False,
            is_trusted=True,
        )
        assert grade == TLSGrade.C
        assert score == 50
        assert any(f["id"] == "TLS_DEPRECATED_V1_1" for f in findings)

    def test_grade_d_tls10(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.0",
            cipher_name="AES128-SHA",
            cipher_bits=128,
            days_remaining=60,
            is_expired=False,
            is_trusted=True,
        )
        assert grade == TLSGrade.D
        assert score == 30
        assert any(f["id"] == "TLS_DEPRECATED_V1_0" for f in findings)

    def test_grade_f_expired_certificate(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="TLSv1.3",
            cipher_name="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            days_remaining=-5,
            is_expired=True,
            is_trusted=True,
        )
        assert grade == TLSGrade.F
        assert score == 0
        assert any(f["id"] == "TLS_CERT_EXPIRED" for f in findings)

    def test_grade_f_handshake_error(self):
        grade, score, findings = calculate_tls_grade(
            tls_version="UNKNOWN",
            cipher_name="NONE",
            cipher_bits=0,
            days_remaining=None,
            is_expired=False,
            is_trusted=False,
            error_msg="Connection reset by peer",
        )
        assert grade == TLSGrade.F
        assert score == 0
        assert any(f["id"] == "TLS_HANDSHAKE_ERROR" for f in findings)


class TestMockTLSInspection:
    def test_default_mock_inspection(self):
        res = get_mock_tls_inspection("test.domain.com", 443)
        assert res["hostname"] == "test.domain.com"
        assert res["port"] == 443
        assert res["connected"] is True
        assert res["tls_version"] == "TLSv1.3"
        assert res["grade"] == "A+"
        assert res["score"] == 100
        assert res["certificate"]["is_expired"] is False
        assert "test.domain.com" in res["certificate"]["subject_alt_names"]

    def test_mock_inspection_with_overrides(self):
        res = get_mock_tls_inspection(
            "legacy.test",
            443,
            custom_data={
                "tls_version": "TLSv1.1",
                "cipher": {"name": "DES-CBC3-SHA", "bits": 112},
            },
        )
        assert res["tls_version"] == "TLSv1.1"
        assert res["grade"] in ["C", "D", "F"]
        assert res["score"] <= 50


class TestInspectTLSAndCert:
    def test_offline_mode_flag(self):
        res = inspect_tls_and_cert("https://example.org", offline_mode=True)
        assert res["hostname"] == "example.org"
        assert res["port"] == 443
        assert res["connected"] is True
        assert res["grade"] == "A+"

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_live_mocked_handshake(self, mock_ctx_factory, mock_create_conn):
        mock_sock = MagicMock()
        mock_create_conn.return_value.__enter__.return_value = mock_sock

        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.selected_alpn_protocol.return_value = "h2"
        mock_ssock.compression.return_value = None
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "test-live.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
            "subjectAltName": (("DNS", "test-live.com"), ("DNS", "www.test-live.com")),
            "serialNumber": "1234567890ABCDEF",
            "version": 3,
        }

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        res = inspect_tls_and_cert("test-live.com", port=443, timeout=3.0)

        assert res["connected"] is True
        assert res["tls_version"] == "TLSv1.3"
        assert res["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
        assert res["cipher"]["bits"] == 256
        assert res["certificate"]["subject"]["commonName"] == "test-live.com"
        assert "www.test-live.com" in res["certificate"]["subject_alt_names"]
        assert res["grade"] == "A+"
        assert res["score"] == 100

    @patch("socket.create_connection", side_effect=TimeoutError("Timed out"))
    def test_timeout_handling(self, mock_conn):
        res = inspect_tls_and_cert("unreachable.test", port=443, timeout=1.0)
        assert res["connected"] is False
        assert res["grade"] == "F"
        assert res["score"] == 0
        assert "timed out" in res["error"].lower()


class TestFormatTLSReport:
    def test_markdown_report_formatting(self):
        mock_res = get_mock_tls_inspection("secure.site.com", 443)
        md = format_tls_markdown_report(mock_res)
        assert "# 🔒 TLS & SSL Certificate Audit: `secure.site.com:443`" in md
        assert "Security Grade:" in md
        assert "Let's Encrypt" in md
        assert "Certificate Details" in md
