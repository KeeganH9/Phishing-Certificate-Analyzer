import argparse
import ipaddress
import socket
import ssl
import time
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlunparse, unquote

import idna
import requests
import tldextract
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.table import Table
from rich.text import Text


console = Console()

#this functions allows input of blank.com or https://blank.com/search 

def normalize_target(target):
    """Return a validated hostname and TLS port."""
    target = target.strip()

    if not target or any(character.isspace() for character in target):
        raise ValueError("Enter a domain or HTTPS URL without spaces.")

    # Allow a bare IPv4 or IPv6 address.
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return str(address), 443

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme.lower() != "https":
        raise ValueError("Use an HTTPS URL or a bare domain.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing usernames or passwords are not supported.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("The URL must contain a hostname.")

    port = parsed.port  # Raises ValueError for invalid ports.
    if port is None:
        port = 443

    if not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535.")

    hostname = hostname.rstrip(".")

    if "%" in hostname:
        raise ValueError("Percent-encoded hosts and IPv6 zone IDs are not supported.")

    try:
        hostname = str(ipaddress.ip_address(hostname))
    except ValueError:
        try:
            hostname = idna.encode(
                hostname, uts46=True, std3_rules=True
            ).decode("ascii").lower()
        except idna.IDNAError as error:
            raise ValueError(f"Invalid domain name: {error}") from error

    return hostname, port

#This connects to port 443 and gets websites certificate and converts whatever format its in to a format that python can look through. it also shows the TLS version and cipher.

def fetch_certificate(hostname, port=443):
    """Retrieve the website certificate and the chain sent by the server."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (hostname, port), timeout=8
    ) as tcp_socket:
        with context.wrap_socket(
            tcp_socket, server_hostname=hostname
        ) as tls_socket:
            certificate_bytes = tls_socket.getpeercert(binary_form=True)
            certificate = x509.load_der_x509_certificate(
                certificate_bytes
            )

            chain = [
                x509.load_der_x509_certificate(cert_bytes)
                for cert_bytes in tls_socket.get_unverified_chain()
            ]

            return {
                "certificate": certificate,
                "chain": chain,
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
    """Match IP addresses against IP entries and domains against DNS entries."""
    hostname = hostname.rstrip(".")

    try:
        target_ip = ipaddress.ip_address(hostname)
    except ValueError:
        target_ip = None

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return False

    if target_ip is not None:
        certificate_ips = san.get_values_for_type(x509.IPAddress)
        return target_ip in certificate_ips

    try:
        ascii_hostname = idna.encode(
            hostname, uts46=True
        ).decode("ascii")
    except idna.IDNAError:
        return False

    certificate_names = san.get_values_for_type(x509.DNSName)

    return any(
        dns_name_matches(ascii_hostname, certificate_name)
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

    # Flag brand names in subdomains of other registered domains.
    domain_parts = get_domain_parts(hostname)
    registered_domain = domain_parts["registered_domain"]
    subdomain = domain_parts["subdomain"]

    known_brand_domains = {
        "paypal": {"paypal.com"},
        "google": {"google.com"},
        "microsoft": {"microsoft.com"},
        "amazon": {"amazon.com"},
        "apple": {"apple.com"},
    }

    subdomain_parts = {
        part
        for label in subdomain.split(".")
        for part in label.split("-")
        if part
    }

    if registered_domain != "Unknown suffix":
        for brand, known_domains in known_brand_domains.items():
            if (
                brand in subdomain_parts
                and registered_domain not in known_domains
            ):
                findings.append({
                    "category": "Domain",
                    "warning": (
                        f"The subdomain contains '{brand}', but the "
                        f"registered domain is '{registered_domain}'. "
                        "Review for possible impersonation."
                    ),
                    "points": 15,
                })

    return findings






#This code is what reads the website calls the functions. prints an error message if applicable
#builds the two terminal tables, calculates the warning points
#displays the the limitations.

domain_extractor = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
)


def get_domain_parts(hostname):
    """Identify the registered domain, subdomain, and public suffix."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return {
            "registered_domain": "Not applicable (IP address)",
            "subdomain": "",
            "suffix": "",
        }

    extracted = domain_extractor(hostname)
    registered_domain = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain and extracted.suffix
        else "Unknown suffix"
    )
    return {
        "registered_domain": registered_domain,
        "subdomain": extracted.subdomain,
        "suffix": extracted.suffix,
    }


def verify_certificate_trust(hostname, port=443):
    """Check certificate trust, validity dates, and hostname."""
    try:
        context = ssl.create_default_context()
        context.hostname_checks_common_name = False

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


class PageParser(HTMLParser):
    """Collect static HTML references; never execute scripts or submit forms."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.passwords = []
        self.current_form = None
        self.base = None
        self.refreshes = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "base" and self.base is None and attrs.get("href"):
            self.base = attrs["href"]
        if tag in ("a", "area") and attrs.get("href"):
            self.links.append(("Link", attrs["href"], "download" in attrs))
        if tag in ("script", "iframe") and attrs.get("src"):
            self.links.append((tag.title(), attrs["src"], False))
        if tag == "form":
            self.current_form = attrs
            self.forms.append(attrs)
        if tag == "input" and (attrs.get("type") or "").lower() == "password":
            self.passwords.append((attrs, self.current_form))
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            self.refreshes.append(attrs.get("content") or "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


def page_url(target, hostname, port):
    """Preserve a supplied URL's path and query, including IPv6/custom ports."""
    raw = target.strip()
    try:
        ipaddress.ip_address(raw)
        path, query = "/", ""
    except ValueError:
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        path, query = parsed.path or "/", parsed.query
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host if port == 443 else f"{host}:{port}"
    return urlunparse(("https", authority, path, "", query, ""))


def inspect_page_html(html, url):
    """Review static HTML; findings are indicators, not malware verdicts."""
    parser = PageParser()
    parser.feed(html)
    findings = []
    seen = set()

    def add(category, warning):
        key = (category, warning)
        if key not in seen:
            seen.add(key)
            findings.append({"category": category, "warning": warning})

    def resolve(reference, base):
        try:
            result = urljoin(base, reference.strip())
            parsed = urlparse(result)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                return None
            # Validate the destination but do not connect to it.
            normalized_host, _ = normalize_target(
                urlunparse(parsed._replace(scheme="https"))
            )
            return result, parsed, normalized_host
        except (ValueError, UnicodeError):
            return None

    base = url
    if parser.base:
        resolved = resolve(parser.base, url)
        if resolved:
            base = resolved[0]
        else:
            add("Coverage", "Unsupported HTML base URL; relative destinations may be inaccurate.")

    domains_checked = set()
    downloads = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".apk")
    for kind, reference, download in parser.links:
        resolved = resolve(reference, base)
        if not resolved:
            continue
        destination, parsed, host = resolved
        if host not in domains_checked:
            domains_checked.add(host)
            for finding in analyze_domain(host):
                add("Destination", f"{host}: {finding['warning']}")
        if kind == "Link" and (download or unquote(parsed.path).lower().endswith(downloads)):
            add("Download review", f"Download link: {destination}. File contents were not checked.")
        if parsed.scheme == "http":
            add("Unencrypted URL", f"{kind} uses HTTP: {destination}")

    by_id = {form.get("id"): form for form in parser.forms if form.get("id")}
    page_host = urlparse(url).hostname
    for attrs, enclosing_form in parser.passwords:
        form = by_id.get(attrs["form"]) if "form" in attrs else enclosing_form
        if form is None:
            add("Form review", "Password input has no resolved form; JavaScript submission is not analyzed.")
            continue
        action = (form.get("action") or "").strip()
        resolved = resolve(action, base) if action else resolve(url, url)
        if not resolved:
            add("Form review", "Password form has an unsupported or invalid submission URL.")
            continue
        destination, parsed, host = resolved
        if parsed.scheme == "http":
            add("Password exposure", f"Password form submits over HTTP: {destination}")
        if host != page_host:
            add("Form review", f"Password form submits to another hostname: {host}. Review the intended login provider.")
        if (form.get("method") or "get").lower() != "post":
            add("Password exposure", "Password form does not declare POST; credentials may appear in a URL.")

    for content in parser.refreshes:
        add("Redirect review", f"HTML refresh directive: {content}. Destination was not followed.")
    return {
        "findings": findings,
        "references": len(parser.links),
        "forms": len(parser.forms),
        "password_inputs": len(parser.passwords),
    }


def analyze_webpage(url):
    """Fetch up to 2 MiB of HTML with TLS verification; never follow links."""
    result = {"status": "Unavailable", "message": "", "findings": [],
              "references": 0, "forms": 0, "password_inputs": 0}
    try:
        with requests.Session() as session:
            # Avoid implicit .netrc credentials and environment proxy settings.
            session.trust_env = False
            with session.get(
                url, timeout=(5, 8), stream=True, allow_redirects=False,
                verify=True, headers={"User-Agent": "PhishCert/1.0", "Accept": "text/html"},
            ) as response:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location", "No Location header")
                    result["message"] = f"HTTP {response.status_code}: redirect to {location}. Redirect not followed; run the destination URL to inspect its HTML."
                    return result
                response.raise_for_status()
                content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if content_type not in ("text/html", "application/xhtml+xml"):
                    result["message"] = f"Response is not declared HTML ({content_type or 'unknown content type'})."
                    return result
                body = bytearray()
                started = time.monotonic()
                partial = False
                for chunk in response.iter_content(chunk_size=16384):
                    if time.monotonic() - started > 20 or len(body) + len(chunk) > 2 * 1024 * 1024:
                        partial = True
                        break
                    body.extend(chunk)
                encoding = response.encoding or "utf-8"
                try:
                    html = body.decode(encoding, errors="replace")
                except LookupError:
                    html = body.decode("utf-8", errors="replace")
                result.update(inspect_page_html(html, url))
                result["status"] = "Partial" if partial else "Completed"
                result["message"] = (
                    "HTML size/time limit reached; only part of the page was inspected."
                    if partial else "Static HTML inspected; linked pages and files were not fetched."
                )
    except (requests.RequestException, ValueError, OSError) as error:
        result["message"] = f"Page analysis unavailable: {error}"
    return result


def print_page_report(result):
    console.print("\nWebpage and Link Analysis", style="bold")
    console.print(f"Status: {result['status']}", markup=False)
    console.print(result["message"], markup=False)
    if result["status"] in ("Completed", "Partial"):
        console.print(
            f"References: {result['references']} | Forms: {result['forms']} | "
            f"Password inputs: {result['password_inputs']}", markup=False,
        )
        table = Table(title="Webpage and Link Findings")
        table.add_column("Category")
        table.add_column("Finding")
        for finding in result["findings"][:100]:
            table.add_row(Text(finding["category"]), Text(finding["warning"]))
        if result["findings"]:
            console.print(table)
            if len(result["findings"]) > 100:
                console.print(f"Showing 100 of {len(result['findings'])} findings.")
        else:
            console.print("No indicators found by the static HTML checks.")
    console.print(
        "Page findings do not add points to the certificate/domain score. "
        "Downloads and external services can be legitimate. "
        "This is not an adware or malware verdict; JavaScript, file contents, "
        "form submission overrides, and reputation blocklists are not checked."
    )

def check_tls_versions(hostname, port=443):
    """Test TLS 1.2 and 1.3 without requesting a webpage."""
    results = []

    versions = [
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.HAS_TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3, ssl.HAS_TLSv1_3),
    ]

    for name, version, available in versions:
        if not available:
            results.append({
                "version": name,
                "status": "Not tested",
                "details": "Your Python/OpenSSL build lacks this version.",
            })
            continue

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version

            with socket.create_connection(
                (hostname, port), timeout=5
            ) as tcp_socket:
                with context.wrap_socket(
                    tcp_socket, server_hostname=hostname
                ) as tls_socket:
                    results.append({
                        "version": name,
                        "status": "Supported",
                        "details": f"Negotiated {tls_socket.version()}.",
                    })

        except (OSError, ValueError) as error:
            results.append({
                "version": name,
                "status": "Inconclusive",
                "details": str(error),
            })

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Inspect a website's certificate and domain."
    )
    parser.add_argument("target", help="Domain or URL to analyze")
    parser.add_argument(
        "--domain-only",
        action="store_true",
        help="Analyze the domain without making network connections."
    )
    args = parser.parse_args()

    try:
        hostname, port = normalize_target(args.target)
        domain_parts = get_domain_parts(hostname)

        if args.domain_only:
            console.print(f"Domain: {hostname}", markup=False)
            console.print("Mode: Offline domain analysis")

            domain_details = Table(title="Domain Details")
            domain_details.add_column("Field")
            domain_details.add_column("Value")
            domain_details.add_row(
                "Registered domain", domain_parts["registered_domain"]
            )
            domain_details.add_row(
                "Subdomain", domain_parts["subdomain"] or "None"
            )
            domain_details.add_row(
                "Public suffix",
                domain_parts["suffix"] or "None identified"
            )
            console.print(domain_details)

            warnings = Table(title="Domain Findings")
            warnings.add_column("Category")
            warnings.add_column("Warning")
            warnings.add_column("Points", justify="right")

            findings = analyze_domain(hostname)

            for finding in findings:
                warnings.add_row(
                    finding["category"],
                    Text(finding["warning"]),
                    str(finding["points"])
                )

            if findings:
                console.print(warnings)
            else:
                console.print("No warnings from the domain checks.")

            score = min(
                sum(finding["points"] for finding in findings), 100
            )
            console.print(
                f"\nProvisional domain risk score: {score}/100"
            )
            console.print(
                "No certificate checks were performed. "
                "This score is not a probability of phishing."
            )
            return

        connection = fetch_certificate(hostname, port)
        certificate = connection["certificate"]
        info = analyze_certificate(certificate)
        trust = verify_certificate_trust(hostname, port)
        tls_results = check_tls_versions(hostname, port)

        findings = evaluate_certificate(hostname, certificate, info)
        findings.extend(analyze_domain(hostname))

        if trust["status"] != "Passed":
            findings.append({
                "category": "Verification",
                "warning": f"{trust['status']}: {trust['message']}",
                "points": 0,
            })

    except (ValueError, OSError) as error:
        console.print(f"Analysis failed: {error}", markup=False)
        return

    page_result = analyze_webpage(
        page_url(args.target, hostname, port)
    )

    # Display certificate and domain details.
    details = Table(title="PhishCert: Certificate Details")
    details.add_column("Field")
    details.add_column("Value")

    details.add_row("Hostname", hostname)
    details.add_row("Port", str(port))
    details.add_row(
        "Registered domain", domain_parts["registered_domain"]
    )
    details.add_row("Subdomain", domain_parts["subdomain"] or "None")
    details.add_row(
        "Public suffix", domain_parts["suffix"] or "None identified"
    )
    details.add_row("Issuer", Text(info["issuer"]))
    details.add_row(
        "Certificate domain names",
        Text(", ".join(info["alternative_names"]) or "No DNS names listed")
    )
    details.add_row("Valid from", str(info["valid_from"]))
    details.add_row("Expires", str(info["valid_until"]))
    details.add_row("Days remaining", str(info["days_remaining"]))
    details.add_row(
        "Negotiated TLS version", str(connection["tls_version"])
    )
    details.add_row(
        "Public key",
        f"{info['key_type']} ({info['key_size']} bits)"
    )
    details.add_row(
        "Signature algorithm", str(info["signature_algorithm"])
    )
    details.add_row("Certificate verification", trust["status"])
    details.add_row("Verification details", Text(trust["message"]))
    console.print(details)

    # Display the certificate chain supplied by the server.
    chain_table = Table(title="Certificate Chain Sent by Server")
    chain_table.add_column("#", justify="right")
    chain_table.add_column("Subject")
    chain_table.add_column("Issuer")
    chain_table.add_column("Expires (UTC)")

    for number, chain_cert in enumerate(connection["chain"], start=1):
        chain_table.add_row(
            str(number),
            Text(chain_cert.subject.rfc4514_string()),
            Text(chain_cert.issuer.rfc4514_string()),
            chain_cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(chain_table)
    console.print(
        "This table shows the certificates supplied by the server. "
        "See Certificate verification for the separate trust-check result."
    )

    # Display the results of the separate TLS-version probes.
    tls_table = Table(title="TLS Version Checks")
    tls_table.add_column("Version")
    tls_table.add_column("Result")
    tls_table.add_column("Details")

    for result in tls_results:
        tls_table.add_row(
            result["version"],
            result["status"],
            Text(result["details"]),
        )

    console.print(tls_table)
    console.print(
        "A failed probe does not prove the server rejects that version. "
        "Local TLS settings or connection problems can also cause failure. "
        "TLS 1.0 and 1.1 are not tested. "
        "Certificate trust is checked separately."
    )

    # Display certificate and domain warnings.
    warnings = Table(title="Findings")
    warnings.add_column("Category")
    warnings.add_column("Warning")
    warnings.add_column("Points", justify="right")

    for finding in findings:
        warnings.add_row(
            finding["category"],
            Text(finding["warning"]),
            str(finding["points"])
        )

    if findings:
        console.print(warnings)
    else:
        console.print(
            "No warnings from the certificate and domain checks."
        )

    # Calculate separate certificate and domain scores.
    certificate_score = min(
        sum(
            finding["points"]
            for finding in findings
            if finding["category"] in ("Certificate", "Cryptography")
        ),
        100,
    )

    domain_score = min(
        sum(
            finding["points"]
            for finding in findings
            if finding["category"] == "Domain"
        ),
        100,
    )

    scores = Table(title="Provisional Scores")
    scores.add_column("Assessment")
    scores.add_column("Score", justify="right")

    scores.add_row(
        "Certificate configuration",
        f"{certificate_score}/100"
    )
    scores.add_row(
        "Domain indicators",
        f"{domain_score}/100"
    )

    console.print(scores)
    console.print(
        "These scores summarize the checks implemented, "
        "not the probability of phishing. "
        "Review certificate verification separately, even when scores are zero. "
        "Webpage findings do not add points."
    )
    console.print(
        "Certificate verification does not establish that a website is safe. "
        "Revocation checking is not implemented."
    )

    # Display the webpage and link findings.
    print_page_report(page_result)


if __name__ == "__main__":
    main()
