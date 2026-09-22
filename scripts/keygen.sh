#!/usr/bin/env bash
# Generate an API key and its sha256 hash for ZeroLLM `api-key` auth.
# A key only ever appears in cleartext at generation time.
set -euo pipefail

KEY="zl_$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 43)"
HASH="$("printf" '%s' "$KEY" | zerollm keys hash)"

echo "key : $KEY"
echo "hash: $HASH"
echo
echo "Put the hash in auth.api_keys[].key_hash and distribute the key to clients."
echo "Verify with:  printf '%s' '<key>' | zerollm keys hash"