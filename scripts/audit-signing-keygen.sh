#!/usr/bin/env bash
# Generate an Ed25519 keypair for ZeroLLM audit-record signing.
# Store the private key where the config's audit.signing.private_key_file
# points; keep the public key offline (or in zerollm.public_key_file) for
# later verification via config.audit.public_key_file / verify_chain().
set -euo pipefail

OUT="${1:-./audit_signing}"
 openssl genpkey -algorithm ED25519 -out "$OUT.private.pem"
 openssl pkey -in "$OUT.private.pem" -pubout -out "$OUT.public.pem"

echo "private: $OUT.private.pem"
echo "public : $OUT.public.pem"
echo
echo "Reference in config:"
echo 'audit:'
echo '  signing:'
echo "    private_key_file: $OUT.private.pem"