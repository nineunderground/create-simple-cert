# create-simple-cert

Generate self-signed wildcard SSL certificates for local development and reverse proxies.

## What it does

Creates a **private key** and a **self-signed certificate** valid for both a base domain and all its subdomains (wildcard).

For example, running it with `my-domain.com` produces a certificate valid for:
- `my-domain.com`
- `*.my-domain.com` (any subdomain)

## Requirements

- Python 3.9+
- `cryptography` package

```bash
pip install cryptography
```

## Usage

```bash
python3 create-cert.py <domain>
```

### Example

```bash
python3 create-cert.py my-domain.com
```

Output:
```
Generating wildcard certificate for: my-domain.com
  Subject Alternative Names: my-domain.com, *.my-domain.com

✅ Private key : my-domain.com.key
✅ Certificate : my-domain.com.crt
```

## Using with a reverse proxy

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name my-domain.com *.my-domain.com;

    ssl_certificate     /path/to/my-domain.com.crt;
    ssl_certificate_key /path/to/my-domain.com.key;

    # ... your config
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

    # ... your config
</VirtualHost>
```

### Caddy

```
*.my-domain.com, my-domain.com {
    tls /path/to/my-domain.com.crt /path/to/my-domain.com.key
    # ... your config
}
```

## ⚠️ Important

This generates **self-signed** certificates. They are suitable for:
- Local development
- Internal services
- Testing environments

Browsers will show a security warning. For production, use a proper CA like [Let's Encrypt](https://letsencrypt.org/).

## License

MIT
