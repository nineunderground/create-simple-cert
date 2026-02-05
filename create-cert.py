#!/usr/bin/env python3
"""
create-cert.py — Obtain a trusted wildcard SSL certificate from Let's Encrypt
using the DNS-01 challenge.

Usage:
    python3 create-cert.py <domain>
    python3 create-cert.py <domain> --staging         # Let's Encrypt staging (testing)
    python3 create-cert.py <domain> --email you@x.com # Expiry notifications

Example:
    python3 create-cert.py my-domain.com

The script will ask you to create DNS TXT records to prove domain ownership,
then download a trusted certificate valid for <domain> and *.<domain>.

Requirements:
    pip install requests cryptography
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time

try:
    import requests
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nInstall with: pip install requests cryptography")


# ---------------------------------------------------------------------------
# ACME directory URLs
# ---------------------------------------------------------------------------

ACME_DIRECTORIES = {
    "production": "https://acme-v02.api.letsencrypt.org/directory",
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")


# ---------------------------------------------------------------------------
# Minimal ACME v2 client (RFC 8555)
# ---------------------------------------------------------------------------

class ACMEClient:
    """Lightweight ACME v2 client that only implements what we need."""

    def __init__(self, directory_url: str, account_key_path: str):
        self._http = requests.Session()
        self._dir_url = directory_url
        self._acct_key_path = account_key_path
        self._key = None          # RSA private key for the ACME account
        self._kid = None          # Account URL (key-id after registration)
        self._directory = None    # ACME directory endpoints
        self._nonce = None        # Replay-nonce

    # -- internal helpers ---------------------------------------------------

    def _jwk(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {
            "e": b64url(_int_bytes(pub.e)),
            "kty": "RSA",
            "n": b64url(_int_bytes(pub.n)),
        }

    def _thumbprint(self) -> str:
        """JWK thumbprint (RFC 7638) — needed for key authorizations."""
        jwk = self._jwk()
        canonical = json.dumps(jwk, separators=(",", ":"), sort_keys=True)
        return b64url(hashlib.sha256(canonical.encode()).digest())

    def _fresh_nonce(self):
        r = self._http.head(self._directory["newNonce"])
        r.raise_for_status()
        self._nonce = r.headers["Replay-Nonce"]

    def _signed_post(self, url: str, payload, _retry: int = 0) -> requests.Response:
        """
        Send a JWS-signed POST to the ACME server.
        payload=None → POST-as-GET (empty payload, per RFC 8555 §6.3).
        """
        if self._nonce is None:
            self._fresh_nonce()

        # Protected header
        protected = {"alg": "RS256", "nonce": self._nonce, "url": url}
        if self._kid:
            protected["kid"] = self._kid
        else:
            protected["jwk"] = self._jwk()

        protected_b64 = b64url(json.dumps(protected).encode())
        payload_b64 = "" if payload is None else b64url(json.dumps(payload).encode())

        signature = self._key.sign(
            f"{protected_b64}.{payload_b64}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(signature),
        }

        resp = self._http.post(
            url, json=body,
            headers={"Content-Type": "application/jose+json"},
        )

        # Update nonce for next request
        if "Replay-Nonce" in resp.headers:
            self._nonce = resp.headers["Replay-Nonce"]

        # Retry once on bad nonce
        if resp.status_code == 400 and _retry < 2:
            try:
                err = resp.json()
                if err.get("type") == "urn:ietf:params:acme:error:badNonce":
                    self._nonce = None
                    return self._signed_post(url, payload, _retry + 1)
            except ValueError:
                pass

        return resp

    # -- public API ---------------------------------------------------------

    def init(self):
        """Fetch the ACME directory and load (or create) the account key."""
        self._directory = self._http.get(self._dir_url).json()

        if os.path.exists(self._acct_key_path):
            with open(self._acct_key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(f.read(), password=None)
            print(f"  Account key : {self._acct_key_path} (loaded)")
        else:
            self._key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048,
            )
            with open(self._acct_key_path, "wb") as f:
                f.write(self._key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
            os.chmod(self._acct_key_path, 0o600)
            print(f"  Account key : {self._acct_key_path} (created)")

    def register(self, email: str | None = None):
        """Register a new ACME account (or find existing)."""
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]

        resp = self._signed_post(self._directory["newAccount"], payload)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Account registration failed ({resp.status_code}):\n{resp.text}")

        self._kid = resp.headers["Location"]
        verb = "Created" if resp.status_code == 201 else "Found existing"
        print(f"  Account     : {verb}")

    def new_order(self, domain: str) -> tuple[dict, str]:
        """Request a new certificate order for domain + *.domain."""
        resp = self._signed_post(self._directory["newOrder"], {
            "identifiers": [
                {"type": "dns", "value": domain},
                {"type": "dns", "value": f"*.{domain}"},
            ],
        })
        if resp.status_code != 201:
            raise RuntimeError(f"Order creation failed ({resp.status_code}):\n{resp.text}")

        return resp.json(), resp.headers["Location"]

    def get_dns_challenges(self, order: dict) -> list[dict]:
        """Extract DNS-01 challenges from order authorizations."""
        challenges = []

        for auth_url in order["authorizations"]:
            auth = self._signed_post(auth_url, None).json()
            identifier = auth["identifier"]["value"]
            is_wildcard = auth.get("wildcard", False)

            for ch in auth["challenges"]:
                if ch["type"] == "dns-01":
                    key_auth = f"{ch['token']}.{self._thumbprint()}"
                    txt_value = b64url(hashlib.sha256(key_auth.encode()).digest())

                    challenges.append({
                        "domain": identifier,
                        "wildcard": is_wildcard,
                        "txt_name": f"_acme-challenge.{identifier}",
                        "txt_value": txt_value,
                        "url": ch["url"],
                    })
                    break

        return challenges

    def submit_challenges(self, challenges: list[dict]):
        """Tell Let's Encrypt we're ready for validation."""
        for ch in challenges:
            resp = self._signed_post(ch["url"], {})
            if resp.status_code not in (200, 202):
                label = f"*.{ch['domain']}" if ch["wildcard"] else ch["domain"]
                raise RuntimeError(
                    f"Challenge submission failed for {label} ({resp.status_code}):\n{resp.text}"
                )

    def poll_order(self, order_url: str, desired: tuple = ("ready", "valid"),
                   timeout: int = 300) -> dict:
        """Poll order URL until it reaches one of the desired statuses."""
        deadline = time.time() + timeout

        while time.time() < deadline:
            resp = self._signed_post(order_url, None)
            order = resp.json()
            status = order.get("status")

            if status in desired:
                return order
            if status == "invalid":
                # Try to extract error details from authorizations
                details = self._get_validation_errors(order)
                raise RuntimeError(
                    f"Order validation FAILED.\n{details}\n"
                    f"Full response:\n{json.dumps(order, indent=2)}"
                )

            print(f"       Status: {status} — checking again in 10s...")
            time.sleep(10)

        raise TimeoutError("Timed out waiting for order to be validated.")

    def _get_validation_errors(self, order: dict) -> str:
        """Pull error details from failed authorizations."""
        errors = []
        for auth_url in order.get("authorizations", []):
            try:
                auth = self._signed_post(auth_url, None).json()
                ident = auth["identifier"]["value"]
                wc = auth.get("wildcard", False)
                label = f"*.{ident}" if wc else ident
                for ch in auth.get("challenges", []):
                    if ch.get("type") == "dns-01" and ch.get("error"):
                        err = ch["error"]
                        errors.append(f"  {label}: {err.get('detail', err)}")
            except Exception:
                pass
        return "\n".join(errors) if errors else "  (no detailed error info available)"

    def finalize_and_download(self, order: dict, order_url: str,
                              domain: str) -> tuple:
        """Send CSR, wait for issuance, download the certificate chain."""
        # Generate private key for the certificate
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build CSR with SANs
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]),
                critical=False,
            )
            .sign(cert_key, hashes.SHA256())
        )

        csr_der = csr.public_bytes(serialization.Encoding.DER)

        # Submit finalization request
        resp = self._signed_post(order["finalize"], {"csr": b64url(csr_der)})
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Finalize failed ({resp.status_code}):\n{resp.text}")

        # Wait for certificate to be issued
        print("       Waiting for certificate issuance...")
        order = self.poll_order(order_url, desired=("valid",))

        cert_url = order.get("certificate")
        if not cert_url:
            raise RuntimeError("Order is valid but no certificate URL found.")

        # Download certificate chain
        resp = self._signed_post(cert_url, None)
        if resp.status_code != 200:
            raise RuntimeError(f"Certificate download failed ({resp.status_code}):\n{resp.text}")

        return cert_key, resp.text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Obtain a trusted wildcard SSL certificate from Let's Encrypt "
            "using the DNS-01 challenge."
        ),
    )
    parser.add_argument("domain", help="Base domain (e.g. my-domain.com)")
    parser.add_argument("--email", help="Contact email (for expiry notifications)")
    parser.add_argument(
        "--staging", action="store_true",
        help="Use Let's Encrypt staging environment (for testing — certs won't be trusted)",
    )
    parser.add_argument(
        "--out", default=".", metavar="DIR",
        help="Output directory for generated files (default: current directory)",
    )
    args = parser.parse_args()

    # Normalize domain
    domain = args.domain.strip().lower()
    if domain.startswith("*."):
        domain = domain[2:]
    if domain.endswith("."):
        domain = domain[:-1]
    if "." not in domain or len(domain) < 4:
        sys.exit(f"Error: '{domain}' is not a valid domain name.")

    env = "staging" if args.staging else "production"

    print()
    print("=" * 58)
    print(f"  Let's Encrypt Wildcard Certificate Generator")
    print(f"  Environment : {env.upper()}")
    print(f"  Domains     : {domain}  *.{domain}")
    print("=" * 58)
    print()

    os.makedirs(args.out, exist_ok=True)
    acct_key_path = os.path.join(args.out, "account.key")

    client = ACMEClient(ACME_DIRECTORIES[env], acct_key_path)

    # Step 1-2: Init & register
    print("[1/6] Initializing ACME client...")
    client.init()

    print("[2/6] Registering account...")
    client.register(args.email)

    # Step 3: Create order
    print(f"[3/6] Creating certificate order...")
    order, order_url = client.new_order(domain)
    print(f"  Order status: {order['status']}")

    # If order is already ready/valid (prior authorizations), skip challenges
    if order["status"] in ("ready", "valid"):
        print("  Authorizations already valid — skipping DNS challenges.")
        challenges = []
    else:
        # Step 4: Get DNS challenges
        print("[4/6] Fetching DNS-01 challenges...")
        challenges = client.get_dns_challenges(order)

        # Display instructions
        print()
        print("─" * 58)
        print("  ✋ ACTION REQUIRED: Create these DNS TXT records")
        print("─" * 58)

        for ch in challenges:
            label = f"*.{ch['domain']}" if ch["wildcard"] else ch["domain"]
            print(f"\n  For: {label}")
            print(f"    Type  : TXT")
            print(f"    Name  : {ch['txt_name']}")
            print(f"    Value : {ch['txt_value']}")

        print()

        # Check if multiple values share the same record name
        names = [ch["txt_name"] for ch in challenges]
        if len(set(names)) < len(names):
            print("  ⚠️  Both challenges use the SAME record name.")
            print("     Add BOTH values as separate TXT records.\n")

        print(f"  Verify your records with:")
        print(f"    nslookup -type=TXT {challenges[0]['txt_name']}")
        print(f"    dig TXT {challenges[0]['txt_name']}")
        print()
        print("─" * 58)
        print()

        try:
            input("Press ENTER when DNS records are in place...")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

        print()

        # Step 5: Submit challenges & wait
        print("[5/6] Submitting challenges & waiting for validation...")
        client.submit_challenges(challenges)
        order = client.poll_order(order_url, desired=("ready", "valid"))
        print("  ✅ Validation successful!")

    # Step 6: Finalize & download
    print("[6/6] Finalizing order & downloading certificate...")
    cert_key, cert_pem = client.finalize_and_download(order, order_url, domain)

    # Save files
    key_path = os.path.join(args.out, f"{domain}.key")
    crt_path = os.path.join(args.out, f"{domain}.crt")

    with open(key_path, "wb") as f:
        f.write(cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

    with open(crt_path, "w") as f:
        f.write(cert_pem)

    print()
    print("✅ Certificate obtained successfully!")
    print()
    print(f"  Private key  : {os.path.abspath(key_path)}")
    print(f"  Certificate  : {os.path.abspath(crt_path)}  (includes full chain)")
    print()
    print("  Nginx example:")
    print(f"    ssl_certificate     {os.path.abspath(crt_path)};")
    print(f"    ssl_certificate_key {os.path.abspath(key_path)};")
    print()
    print("  📌 Certificate is valid for 90 days. Set a reminder to renew!")
    print(f"  💡 You can now remove the _acme-challenge TXT record(s) from your DNS.")
    print()


if __name__ == "__main__":
    main()
