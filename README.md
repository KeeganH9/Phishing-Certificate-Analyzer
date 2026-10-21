Phishing-Certificate-Analyzer
For editors: go into the code space ,improved orbit and copy the code into VS
and you should see the same readme as below, as well as analyzer.py (main file) and test_analyzer.py (test file)

Requirements
- Python 3.13 or newer for the certificate-chain API used by this version. We tested these scripts using Python 3.14.7 but we have not tested all other versions.
- The analyzer.py file.
- The packages cryptography, requests, idna, tldextract, and rich.
- For tests: pytest and test_analyzer.py.
- An internet connection for certificate, TLS-version, and webpage checks. Domain-only mode works offline after package installation.
Python includes argparse, ipaddress, socket, ssl, datetime, urllib.parse, time, and html.parser. The tests also use Python's sys and unittest.mock modules.

Using Python version 3.14.7

Open Command Prompt and run:

python --version
python -m pip --version

make a directory for the files, mine is 

cd /d "C:\Users\keegan\Documents\PhishCert"

The cd command enters an existing folder. Create the PhishCert folder first if needed, and put analyzer.py and test_analyzer.py inside it. Replace this path with your own folder path, including OneDrive if that is where you keep the files.

Then you will need to create and activate a VE(virtual Envirment) using the commands in command prompt:

python -m venv .venv
.venv\Scripts\activate.bat

you should see (.venv) before the directory this means you are ready. 

Then install depenencies:
python -m pip install cryptography requests idna tldextract rich

For the test run:
python -m pip install pytest

To actually use the anayzer run the command:
python analyzer.py example.com

Replace example.com with the domain you want to inspect. You can also enter an HTTPS URL with a page path or a custom TLS port:

python analyzer.py "https://example.com/login"
python analyzer.py "https://example.com:8443/login"

The custom-port example only works if the server accepts TLS on that port. Without a specified port, the analyzer uses port 443. Use quotes around URLs, especially if they contain query parameters such as &.

For domain checks without making network connections, run:

python analyzer.py paypal.com.example.org --domain-only

This mode displays the domain breakdown, domain warnings, and domain score. It skips certificate retrieval, trust verification, TLS probes, and webpage retrieval.

To see the command options, run:

python analyzer.py --help

Then if you close it and want to reopen use command:

cd /d "C:\Users\keegan\Documents\PhishCert"
.venv\Scripts\activate.bat
python analyzer.py example.com

You only need to create the virtual environment once. Activate it when opening a new Command Prompt for the project.

you can leave the VE with the command: deactivate

To run the test run the command: 

python -m pytest test_analyzer.py -v

The current test file contains 17 tests. A successful run shows 17 passed. The tests use sample data and simulated connection failures without contacting websites. They cover selected behaviors, not every possible error or website.

If Python says No module named pytest, activate the virtual environment and run python -m pip install pytest. For another missing project package, rerun the dependency installation command above in that same environment.

If your output does not match your latest edits, save the file and check which copy Python loads:

python -c "import analyzer; print(analyzer.file)"

The files analyzer.py and test_analyzer.py are in the codespace.

What the report includes
- Certificate details: issuer, certificate DNS names, validity dates, days remaining, signature algorithm, public key type and size, and the negotiated TLS version.
- Certificate verification: Passed, Failed, or Inconclusive, with the verification message.
- Certificate chain sent by the server: each supplied certificate's subject, issuer, and expiration date. This table does not establish trust; review the separate verification result.
- TLS version checks: separate connection attempts using TLS 1.2 and TLS 1.3. Supported means the connection succeeded with that version. Inconclusive means the probe failed without establishing the cause. Not tested means the local Python/OpenSSL build lacks that version.
- Domain details: registered domain, subdomain, and public suffix. These describe the domain structure, not verified ownership.
- Findings: certificate warnings and domain indicators with their assigned points.
- Provisional Scores: separate certificate configuration and domain indicator scores, each capped at 100.
- Webpage and Link Analysis: static HTML checks for suspicious destination names, download links, HTTP references, password-form concerns, and HTML refresh directives.
How the scores work

Certificate configuration points:
- Expired certificate: 40 points.
- Certificate not valid yet: 40 points.
- Hostname mismatch: 35 points.
- Apparent self-signed certificate: 25 points. This heuristic compares the subject and issuer; it does not verify the self-signature.
- RSA key smaller than 2048 bits: 25 points.
- Elliptic-curve key smaller than 256 bits: 25 points.
- MD5 or SHA-1 signature algorithm: 30 points.
- Certificate expires within 30 days: a warning with 0 points.
Domain indicator points:
- IP address instead of a domain: 10 points.
- Punycode use or invalid Punycode: 5 points.
- Keywords such as login, verify, account, secure, or update: 5 points total.
- A recognized digit-substitution brand lookalike: 15 points per detected occurrence.
- A recognized brand in the subdomain of a domain outside the small reference list: 15 points per matched brand.
Verification findings add 0 points to avoid counting the same certificate issue twice. A verification failure can therefore appear alongside a certificate score of 0. Read the verification result as well as the scores.

TLS-version probes and webpage findings do not add score points. The scores summarize the implemented rules; they are not percentages or probabilities of phishing. A score of 0 does not prove a site is safe, and 100 does not prove phishing.

Webpage analysis details and limitations

The normal command requests the target page's HTML and inspects its links and forms. A URL's path and query determine which page it requests. The analyzer verifies TLS for this request and does not bypass a failed certificate check to fetch the page.

The analyzer does not execute JavaScript, follow page links, download linked files, or submit forms. It reports HTTP redirects without following them. To inspect a redirect destination, run the analyzer with that destination's HTTPS URL.

The HTML reader limits content to 2 MiB and checks a 20-second reading budget between chunks, with separate connection and read timeouts. Partial means it inspected only part of the HTML. Unavailable means it could not inspect the page, for example because of a redirect, TLS error, HTTP error, timeout, or non-HTML response. A page-fetch failure preserves the certificate and domain report when those earlier checks completed; a failure during initial certificate retrieval stops the run.

These checks do not confirm adware or malware. Legitimate websites can offer executable downloads, use external login providers, and contain the keywords that the analyzer flags. The analyzer does not check file contents, reputation blocklists, JavaScript-generated behavior, or certificate revocation. It tests TLS 1.2 and 1.3, not TLS 1.0 or 1.1. The domain checks use a bundled suffix list and a small brand reference list, so they can miss threats or flag legitimate names.

Quick summary of the scripts and how they work

In analyzer.py, main() reads your target, validates the hostname and port, and identifies the domain parts. In a normal run, it retrieves the certificate and server-supplied chain, checks certificate details and trust, probes TLS 1.2 and 1.3, and examines the domain for review indicators. It then fetches static HTML for the webpage checks and prints the tables, warnings, and separate scores. With --domain-only, it checks only the domain text and exits before making network connections.

In test_analyzer.py, the 17 pytest tests check selected certificate, domain, webpage, and TLS-error behaviors using sample inputs and mocked network functions. They also check that domain-only mode skips the network functions. Run the tests after editing the code to help catch regressions.
