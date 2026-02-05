#!/bin/bash
set -e

# Run the certificate script with all passed arguments
python3 /app/create-cert.py --out /tmp/certs "$@"

# If successful, output the certificate files
if [ $? -eq 0 ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  CERTIFICATE FILES — Copy and save these locally"
    echo "═══════════════════════════════════════════════════════════════"
    
    for keyfile in /tmp/certs/*.key; do
        if [ -f "$keyfile" ] && [ "$(basename "$keyfile")" != "account.key" ]; then
            filename=$(basename "$keyfile")
            echo ""
            echo "──────────────────────────────────────────────────────────────"
            echo "  FILE: $filename"
            echo "──────────────────────────────────────────────────────────────"
            cat "$keyfile"
            echo ""
        fi
    done
    
    for crtfile in /tmp/certs/*.crt; do
        if [ -f "$crtfile" ]; then
            filename=$(basename "$crtfile")
            echo "──────────────────────────────────────────────────────────────"
            echo "  FILE: $filename"
            echo "──────────────────────────────────────────────────────────────"
            cat "$crtfile"
            echo ""
        fi
    done
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Save the above contents to $filename and $(basename "${keyfile}")"
    echo "═══════════════════════════════════════════════════════════════"
fi
