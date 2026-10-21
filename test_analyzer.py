
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

def test_misleading_subdomain():
    findings = analyzer.analyze_domain("paypal.com.example.org")

    assert any(
        "subdomain contains 'paypal'" in finding["warning"]
        and "registered domain is 'example.org'" in finding["warning"]
        and finding["points"] == 15
        for finding in findings
    )


def test_brand_subdomain_on_known_domain():
    findings = analyzer.analyze_domain("paypal.paypal.com")

    assert not any(
        "possible impersonation" in finding["warning"]
        for finding in findings
    )


def test_registered_domain_breakdown():
    parts = analyzer.get_domain_parts("paypal.com.example.org")

    assert parts == {
        "registered_domain": "example.org",
        "subdomain": "paypal.com",
        "suffix": "org",
    }


def test_webpage_suspicious_link():
    html = '<a href="https://paypa1.example">Sign in</a>'

    result = analyzer.inspect_page_html(html, "https://example.com")

    assert any(
        finding["category"] == "Destination"
        and "resembles 'paypal'" in finding["warning"]
        for finding in result["findings"]
    )


def test_webpage_download_link():
    html = '<a href="/files/setup.exe">Download</a>'

    result = analyzer.inspect_page_html(html, "https://example.com")

    assert any(
        finding["category"] == "Download review"
        and "https://example.com/files/setup.exe" in finding["warning"]
        for finding in result["findings"]
    )


def test_webpage_insecure_password_form():
    html = """
        <form action="http://example.com/login" method="post">
            <input type="password" name="password">
        </form>
    """

    result = analyzer.inspect_page_html(html, "https://example.com")

    assert any(
        finding["category"] == "Password exposure"
        and "submits over HTTP" in finding["warning"]
        for finding in result["findings"]
    )


def test_webpage_refresh():
    html = '<meta http-equiv="refresh" content="5;url=/next">'

    result = analyzer.inspect_page_html(html, "https://example.com")

    assert any(
        finding["category"] == "Redirect review"
        for finding in result["findings"]
    )


def test_webpage_without_indicators():
    html = """
        <a href="/about">About us</a>
        <form action="/login" method="post">
            <input type="password" name="password">
        </form>
    """

    result = analyzer.inspect_page_html(html, "https://example.com")

    assert result["findings"] == []


def test_tls_connection_failure_is_inconclusive(monkeypatch):
    from unittest.mock import MagicMock

    # Simulate local TLS support without relying on this computer's settings.
    monkeypatch.setattr(analyzer.ssl, "HAS_TLSv1_2", True)
    monkeypatch.setattr(analyzer.ssl, "HAS_TLSv1_3", True)
    monkeypatch.setattr(
        analyzer.ssl, "SSLContext", MagicMock()
    )

    attempts = []

    def fail_connection(address, timeout):
        attempts.append(address)
        raise OSError("Simulated connection failure")

    monkeypatch.setattr(
        analyzer.socket, "create_connection", fail_connection
    )

    results = analyzer.check_tls_versions("example.com", 8443)

    assert len(results) == 2
    assert attempts == [
        ("example.com", 8443),
        ("example.com", 8443),
    ]
    assert all(
        result["status"] == "Inconclusive"
        and "Simulated connection failure" in result["details"]
        for result in results
    )


def test_domain_only_skips_network(monkeypatch, capsys):
    import sys
    from rich.console import Console

    def unexpected_network_call(*args, **kwargs):
        raise AssertionError("Offline mode attempted a network operation")

    monkeypatch.setattr(
        sys, "argv",
        ["analyzer.py", "paypal.com.example.org", "--domain-only"]
    )
    monkeypatch.setattr(
        analyzer, "console",
        Console(force_terminal=False, width=120)
    )

    for function_name in (
        "fetch_certificate",
        "verify_certificate_trust",
        "check_tls_versions",
        "analyze_webpage",
    ):
        monkeypatch.setattr(
            analyzer, function_name, unexpected_network_call
        )

    analyzer.main()

    output = capsys.readouterr().out
    assert "Offline domain analysis" in output
    assert "15/100" in output
