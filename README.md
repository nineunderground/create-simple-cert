# create-simple-cert

Obtain a **trusted wildcard SSL certificate** from [Let's Encrypt](https://letsencrypt.org/) using the DNS-01 challenge — in a single Python script.

## What it does

1. Connects to Let's Encrypt's ACME v2 API
2. Requests a certificate for your domain **and** all subdomains (wildcard)
3. Asks you to create DNS TXT records to prove you own the domain
4. Downloads the trusted certificate + full chain once validated

The resulting certificate is **publicly trusted** — no browser warnings, no self-signed certs.

## Requirements

- Python 3.9+ (or Docker)
- Domain you own with access to its DNS settings

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 create-cert.py <domain>
```

### Example

```bash
python3 create-cert.py my-domain.com
```

The script will display DNS TXT records to create:

```
─────────────────────────────────────────────────────
  ✋ ACTION REQUIRED: Create these DNS TXT records
─────────────────────────────────────────────────────

  For: my-domain.com
    Type  : TXT
    Name  : _acme-challenge.my-domain.com
    Value : aB3dEfGhIjKlMnOpQrStUvWxYz...

  For: *.my-domain.com
    Type  : TXT
    Name  : _acme-challenge.my-domain.com
    Value : zYxWvUtSrQpOnMlKjIhGfEdCbA...

  ⚠️  Both challenges use the SAME record name.
     Add BOTH values as separate TXT records.

Press ENTER when DNS records are in place...
```

After you create the records and press ENTER:

```
✅ Certificate obtained successfully!

  Private key  : /path/to/my-domain.com.key
  Certificate  : /path/to/my-domain.com.crt  (includes full chain)
```

### Options

| Flag | Description |
|------|-------------|
| `--email you@example.com` | Contact email for expiry notifications |
| `--staging` | Use Let's Encrypt staging (for testing — certs won't be browser-trusted) |
| `--out DIR` | Output directory for generated files |

### Testing with staging

Always test with `--staging` first to avoid hitting [rate limits](https://letsencrypt.org/docs/rate-limits/):

```bash
python3 create-cert.py my-domain.com --staging
```

## Docker usage

Build the image:

```bash
docker build -t create-simple-cert .
```

Run interactively (required for DNS challenge confirmation):

```bash
docker run -it create-simple-cert my-domain.com
```

With email for expiry notifications:

```bash
docker run -it create-simple-cert my-domain.com --email you@example.com
```

Test with staging first:

```bash
docker run -it create-simple-cert my-domain.com --staging
```

The container will:
1. Show you the DNS TXT records to create
2. Wait for you to press ENTER after creating them
3. Print the **full certificate and private key contents** to stdout

Copy the output and save to `my-domain.com.crt` and `my-domain.com.key` locally.

## Output files

| File | Description |
|------|-------------|
| `<domain>.key` | RSA 2048 private key (permissions: 600) |
| `<domain>.crt` | Certificate + full chain (PEM) |
| `account.key` | ACME account key (reused across runs) |

## Reverse proxy configuration

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name my-domain.com *.my-domain.com;

    ssl_certificate     /path/to/my-domain.com.crt;
    ssl_certificate_key /path/to/my-domain.com.key;
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName my-domain.com
    ServerAlias *.my-domain.com

    SSLEngine on
    SSLCertificateFile    /path/to/my-domain.com.crt
    SSLCertificateKeyFile /path/to/my-domain.com.key
</VirtualHost>
```

### Caddy

```
*.my-domain.com, my-domain.com {
    tls /path/to/my-domain.com.crt /path/to/my-domain.com.key
}
```

## How it works

- Uses the **ACME v2 protocol** ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)) to communicate with Let's Encrypt
- Proves domain ownership via **DNS-01 challenge** — the only challenge type that supports wildcard certificates
- No external tools needed (no certbot, no acme.sh) — just Python and two pip packages

## Certificate renewal

Let's Encrypt certificates are valid for **90 days**. To renew, simply run the script again and update the DNS TXT records. The existing `account.key` will be reused automatically.

## License

MIT
