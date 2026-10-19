import argparse
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import idna
import requests
import tldextract
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.table import Table


console = Console()

#this functions allows input of blank.com or https://blank.com/search 

def normalize_target(target):
    """Convert a URL or domain into a hostname."""
    if "://" not in target:
        target = "https://" + target

    parsed_url = urlparse(target)
    hostname = parsed_url.hostname

    if not hostname:
        raise ValueError("Please enter a valid website or domain.")

    return hostname.lower()

#This connects to port 443 and gets websites certificate and converts whatever format its in to a format that python can look through. it also shows the TLS version and cipher.

def fetch_certificate(hostname, port=443):
    """Connect to a website and retrieve its TLS certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=8) as tcp_socket:
        with context.wrap_socket(
            tcp_socket,
            server_hostname=hostname
        ) as tls_socket:
            certificate_bytes = tls_socket.getpeercert(binary_form=True)

            certificate = x509.load_der_x509_certificate(
                certificate_bytes
            )

            return {
                "certificate": certificate,
                "tls_version": tls_socket.version(),
                "cipher": tls_socket.cipher(),
            }


#This function extracts the certificate info. All the info returned is the certificate info from lines 90-99.
def analyze_certificate(certificate):
    """Extract important security details from an X.509 certificate."""
    public_key = certificate.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = "Elliptic Curve"
        key_size = public_key.key_size
    else:
        key_type = type(public_key).__name__
        key_size = getattr(public_key, "key_size", "Unknown")

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        alternative_names = san_extension.value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        alternative_names = []

    expiration_date = certificate.not_valid_after_utc
    days_remaining = (expiration_date - datetime.now(timezone.utc)).days

    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "valid_from": certificate.not_valid_before_utc,
        "valid_until": expiration_date,
        "days_remaining": days_remaining,
        "alternative_names": alternative_names,
        "signature_algorithm": certificate.signature_algorithm_oid._name,
        "key_type": key_type,
        "key_size": key_size,
        "self_signed": certificate.subject == certificate.issuer,
    }

#This checks blank.com or *.blank.com and stops a wildcard from matching to multiple subdomains.
def dns_name_matches(hostname, certificate_name):
    """Check a hostname against a certificate DNS name."""
    hostname = hostname.lower().rstrip(".")
    certificate_name = certificate_name.lower().rstrip(".")

    if certificate_name.startswith("*."):
        hostname_parts = hostname.split(".")
        certificate_parts = certificate_name.split(".")

        return (
            len(hostname_parts) == len(certificate_parts)
            and hostname_parts[1:] == certificate_parts[1:]
        )

    return hostname == certificate_name


def check_hostname_match(hostname, certificate):
    """Check whether the certificate covers the requested hostname."""
    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        certificate_names = san_extension.value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        common_names = certificate.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        certificate_names = [name.value for name in common_names]

    return any(
        dns_name_matches(hostname, certificate_name)
        for certificate_name in certificate_names
    )


#This assigns the points to expired, wrong, self signed, or cryptographic weak certificates
#This is the scoring rules for each website.

def evaluate_certificate(hostname, certificate, certificate_info):
    """Create risk findings based on certificate problems."""
    findings = []
    if certificate_info["valid_from"] > datetime.now(timezone.utc):
        findings.append({
            "category": "Certificate",
            "warning": "The certificate is not valid yet.",
            "points": 40,
        })

    if certificate_info["days_remaining"] < 0:
        findings.append({
            "category": "Certificate",
            "warning": "The certificate has expired.",
            "points": 40,
        })
    elif certificate_info["days_remaining"] <= 30:
        findings.append({
            "category": "Certificate",
            "warning": "The certificate expires within 30 days.",
            "points": 0,
        })

    if not check_hostname_match(hostname, certificate):
        findings.append({
            "category": "Certificate",
            "warning": "The certificate does not match the hostname.",
            "points": 35,
        })

    if certificate_info["self_signed"]:
        findings.append({
            "category": "Certificate",
            "warning": "The certificate appears to be self signed.",
            "points": 25,
        })

    if (
        certificate_info["key_type"] == "RSA"
        and isinstance(certificate_info["key_size"], int)
        and certificate_info["key_size"] < 2048
    ):
        findings.append({
            "category": "Cryptography",
            "warning": "The RSA public key is smaller than 2048 bits.",
            "points": 25,
        })

    if (
        certificate_info["key_type"] == "Elliptic Curve"
        and isinstance(certificate_info["key_size"], int)
        and certificate_info["key_size"] < 256
    ):
        findings.append({
            "category": "Cryptography",
            "warning": "The elliptic-curve key is smaller than 256 bits.",
            "points": 25,
        })

    signature = certificate_info["signature_algorithm"].lower()

    if "md5" in signature or "sha1" in signature:
        findings.append({
            "category": "Cryptography",
            "warning": (
                f"Weak certificate signature algorithm detected: "
                f"{certificate_info['signature_algorithm']}."
            ),
            "points": 30,
        })

    return findings

#These are small indicators but does not show proof of phishing.
def analyze_domain(hostname):
    """Flag domain features for review without connecting to the website."""
    findings = []
    hostname = hostname.lower().rstrip(".")

    # Check whether the target is an IP address.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        findings.append({
            "category": "Domain",
            "warning": "The target uses an IP address instead of a domain.",
            "points": 10,
        })
        return findings

    labels = hostname.split(".")

    # Decode Punycode so the user can review the spelling.
    if any(label.startswith("xn--") for label in labels):
        try:
            decoded_domain = idna.decode(hostname)
            warning = (
                f"The domain uses Punycode: {decoded_domain}. "
                "Review the spelling for lookalike characters."
            )
        except idna.IDNAError:
            warning = "The domain contains invalid Punycode."

        findings.append({
            "category": "Domain",
            "warning": warning,
            "points": 5,
        })

    # Flag keywords as weak indicators for review.
    keywords = ("login", "verify", "account", "secure", "update")
    matched_keywords = [
        keyword for keyword in keywords if keyword in hostname
    ]

    if matched_keywords:
        findings.append({
            "category": "Domain",
            "warning": (
                "Review domain keywords: " + ", ".join(matched_keywords)
            ),
            "points": 5,
        })

    # Check a small list of brands for digit substitutions.
    brands = ("paypal", "google", "microsoft", "amazon", "apple")
    substitutions = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
    })

    for label in labels:
        for part in label.split("-"):
            normalized = part.translate(substitutions)

            if normalized in brands and part != normalized:
                findings.append({
                    "category": "Domain",
                    "warning": (
                        f"Possible brand lookalike: '{part}' "
                        f"resembles '{normalized}'."
                    ),
                    "points": 15,
                })

    return findings

#This checks the certificate chain, the dates and the hostname 
#This makes 1 TLS connection.
def verify_certificate_trust(hostname, port=443):
    """Check certificate trust, validity, and hostname using Python's TLS verifier."""
    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port), timeout=8
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket, server_hostname=hostname
            ):
                return {
                    "status": "Passed",
                    "message": "Certificate verification succeeded.",
                }

    except ssl.SSLCertVerificationError as error:
        return {
            "status": "Failed",
            "message": error.verify_message,
        }

    except OSError as error:
        return {
            "status": "Inconclusive",
            "message": str(error),
        }







#This code is what reads the website calls the functions. prints an error message if applicable
#builds the two terminal tables, calculates the warning points
#displays the the limitations.

def main():
    parser = argparse.ArgumentParser(
        description="Inspect a website's certificate and domain."
    )
    parser.add_argument("target", help="Domain or URL to analyze")
    args = parser.parse_args()

    try:
        hostname = normalize_target(args.target)
        connection = fetch_certificate(hostname)
        certificate = connection["certificate"]
        info = analyze_certificate(certificate)
        trust = verify_certificate_trust(hostname)

        findings = evaluate_certificate(hostname, certificate, info)
        findings.extend(analyze_domain(hostname))
        if trust["status"] != "Passed":
            findings.append({
                "category": "Verification",
                "warning": (
                    f"{trust['status']}: {trust['message']}"
                ),
                "points": 0,
            })

    except (ValueError, OSError) as error:
        console.print(f"Analysis failed: {error}", markup=False)
        return

    details = Table(title="PhishCert: Certificate Details")
    details.add_column("Field")
    details.add_column("Value")

    details.add_row("Hostname", hostname)
    details.add_row("Issuer", info["issuer"])
    details.add_row(
        "Certificate domain names",
        ", ".join(info["alternative_names"]) or "No DNS names listed"
    )
    details.add_row("Valid from", str(info["valid_from"]))
    details.add_row("Expires", str(info["valid_until"]))
    details.add_row("Days remaining", str(info["days_remaining"]))
    details.add_row("Negotiated TLS version", str(connection["tls_version"]))
    details.add_row(
        "Public key",
        f"{info['key_type']} ({info['key_size']} bits)"
    )
    details.add_row("Signature algorithm", str(info["signature_algorithm"]))
    details.add_row("Certificate verification", trust["status"])
    details.add_row("Verification details", trust["message"])
    console.print(details)

    warnings = Table(title="Findings")
    warnings.add_column("Category")
    warnings.add_column("Warning")
    warnings.add_column("Points", justify="right")

    for finding in findings:
        warnings.add_row(
            finding["category"],
            finding["warning"],
            str(finding["points"])
        )

    if findings:
        console.print(warnings)
    else:
        console.print("No warnings from the checks implemented so far.")

    score = min(sum(finding["points"] for finding in findings), 100)
    console.print(f"\nProvisional risk score: {score}/100")
    console.print("This score is not a probability of phishing.")
    console.print(
        "Certificate verification does not establish that a website is safe. "
        "Revocation checking is not implemented."
    )


if __name__ == "__main__":
    main()





