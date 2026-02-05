#!/usr/bin/env python3
"""
create-cert.py — Generate a self-signed wildcard SSL certificate for a given domain.

Usage:
    python3 create-cert.py <domain>

Example:
    python3 create-cert.py my-domain.com

Produces:
    <domain>.key  — Private key (RSA 2048)
    <domain>.crt  — Self-signed certificate valid for <domain> and *.<domain>
"""

import sys
import datetime
import os

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("Error: 'cryptography' package is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


def create_wildcard_cert(domain: str, days_valid: int = 365) -> tuple[str, str]:
    """
    Generate a self-signed wildcard certificate and private key for the given domain.

    Returns a tuple of (key_path, cert_path).
    """
    # Generate RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject / Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"*.{domain}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    # Subject Alternative Names: bare domain + wildcard
    san = x509.SubjectAlternativeName([
        x509.DNSName(domain),
        x509.DNSName(f"*.{domain}"),
    ])

    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    key_path = f"{domain}.key"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)

    # Write certificate
    cert_path = f"{domain}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path


def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        sys.exit(0 if sys.argv[-1] in ("-h", "--help") else 1)

    domain = sys.argv[1].strip().lower()

    # Basic validation
    if domain.startswith("*."):
        domain = domain[2:]
        print(f"Note: Stripped wildcard prefix. Using base domain: {domain}")

    if "." not in domain or len(domain) < 3:
        print(f"Error: '{domain}' doesn't look like a valid domain.")
        sys.exit(1)

    print(f"Generating wildcard certificate for: {domain}")
    print(f"  Subject Alternative Names: {domain}, *.{domain}")
    print()

    key_path, cert_path = create_wildcard_cert(domain)

    print(f"✅ Private key : {key_path}")
    print(f"✅ Certificate : {cert_path}")
    print()
    print("Usage in a reverse proxy (e.g., Nginx):")
    print(f"  ssl_certificate     /path/to/{cert_path};")
    print(f"  ssl_certificate_key /path/to/{key_path};")


if __name__ == "__main__":
    main()
