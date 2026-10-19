
#This uses fake certificate details with a false info to check for warning.

from datetime import datetime, timedelta, timezone

import analyzer


def test_certificate_not_valid_yet(monkeypatch):
    # Isolate the date check by assuming the hostname matches.
    monkeypatch.setattr(
        analyzer, "check_hostname_match",
        lambda hostname, certificate: True
    )

    info = {
        "valid_from": datetime.now(timezone.utc) + timedelta(days=1),
        "days_remaining": 90,
        "self_signed": False,
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
    }

    findings = analyzer.evaluate_certificate(
        "example.com", None, info
    )

    assert any(
        finding["warning"] == "The certificate is not valid yet."
        and finding["points"] == 40
        for finding in findings
    )

def test_punycode_decoding():
    findings = analyzer.analyze_domain("xn--bcher-kva.example")

    assert any(
        "bücher.example" in finding["warning"]
        and finding["points"] == 5
        for finding in findings
    )

def test_domain_keywords():
    findings = analyzer.analyze_domain("secure-login.example")

    assert any(
        "login" in finding["warning"]
        and "secure" in finding["warning"]
        and finding["points"] == 5
        for finding in findings
    )


def test_ip_address():
    findings = analyzer.analyze_domain("192.0.2.1")

    assert any(
        finding["warning"] == (
            "The target uses an IP address instead of a domain."
        )
        and finding["points"] == 10
        for finding in findings
    )


def test_plain_domain_has_no_warnings():
    assert analyzer.analyze_domain("example.com") == []

def test_brand_lookalike():
    findings = analyzer.analyze_domain("paypa1.example")

    assert any(
        "resembles 'paypal'" in finding["warning"]
        and finding["points"] == 15
        for finding in findings
    )


def test_correct_brand_spelling():
    findings = analyzer.analyze_domain("paypal.com")

    assert not any(
        "Possible brand lookalike" in finding["warning"]
        for finding in findings
    )