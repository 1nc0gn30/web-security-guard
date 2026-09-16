"""Unit tests for web_security_guard.presets module."""

from __future__ import annotations

import pytest

from web_security_guard.presets import (
    PRESETS,
    create_api_service_preset,
    create_creative_media_preset,
    create_developer_portal_preset,
    create_ecommerce_pci_preset,
    create_saas_enterprise_preset,
    create_strict_zero_trust_preset,
    get_preset,
    get_preset_metadata,
    list_presets,
)


def test_list_presets() -> None:
    presets = list_presets()
    expected = [
        "strict_zero_trust",
        "saas_enterprise",
        "ecommerce_pci",
        "developer_portal",
        "api_service",
        "creative_media",
    ]
    for exp in expected:
        assert exp in presets


def test_get_preset_metadata() -> None:
    meta = get_preset_metadata("strict_zero_trust")
    assert meta["name"] == "strict_zero_trust"
    assert "Strict Zero Trust" in meta["title"]
    assert len(meta["compliance"]) > 0
    assert "recommended_for" in meta

    with pytest.raises(KeyError, match="Unknown preset"):
        get_preset_metadata("non_existent_preset")


def test_strict_zero_trust_preset() -> None:
    builder = create_strict_zero_trust_preset(nonce="staticNonce123", report_uri="https://api.example.com/report")
    policy = builder.build()

    assert "default-src 'none'" in policy
    assert "'nonce-staticNonce123'" in policy
    assert "'strict-dynamic'" in policy
    assert "object-src 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "upgrade-insecure-requests" in policy
    assert "require-trusted-types-for 'script'" in policy
    assert "report-uri https://api.example.com/report" in policy


def test_saas_enterprise_preset() -> None:
    builder = create_saas_enterprise_preset(
        nonce="saasNonce999",
        api_domains=["https://api.mycorp.internal", "wss://events.mycorp.internal"],
    )
    policy = builder.build()

    assert "default-src 'self'" in policy
    assert "https://api.mycorp.internal" in policy
    assert "wss://events.mycorp.internal" in policy
    assert "https://fonts.googleapis.com" in policy
    assert "https://fonts.gstatic.com" in policy
    assert "'nonce-saasNonce999'" in policy


def test_ecommerce_pci_preset() -> None:
    builder = create_ecommerce_pci_preset(
        nonce="pciNonce777",
        payment_gateways=["https://js.stripe.com", "https://custom.pay.com"],
    )
    policy = builder.build()

    assert "default-src 'none'" in policy
    assert "https://js.stripe.com" in policy
    assert "https://custom.pay.com" in policy
    assert "object-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "'nonce-pciNonce777'" in policy


def test_developer_portal_preset() -> None:
    builder = create_developer_portal_preset()
    policy = builder.build()

    assert "default-src 'self'" in policy
    assert "'unsafe-eval'" in policy
    assert "https://cdn.jsdelivr.net" in policy
    assert "worker-src 'self' blob:" in policy


def test_api_service_preset() -> None:
    builder = create_api_service_preset(report_uri="https://api.example.com/csp-report")
    policy = builder.build()

    assert "default-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "sandbox" in policy
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy
    assert "object-src 'none'" in policy


def test_creative_media_preset() -> None:
    builder = create_creative_media_preset(nonce="mediaNonce555")
    policy = builder.build()

    assert "'wasm-unsafe-eval'" in policy
    assert "media-src 'self' blob: data: https:" in policy
    assert "worker-src 'self' blob:" in policy
    assert "'nonce-mediaNonce555'" in policy


def test_get_preset_factory_dispatcher() -> None:
    for name in PRESETS:
        b = get_preset(name)
        assert b is not None
        assert len(b.build()) > 0

    with pytest.raises(KeyError, match="Unknown preset"):
        get_preset("invalid_preset_name")
