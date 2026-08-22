#!/bin/sh
set -eu

HASHCAT_WORDLIST=/app/wordlists/10k-most-common.txt
SECLISTS_WORDLIST_URL=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt

if [ ! -s "$HASHCAT_WORDLIST" ]; then
  mkdir -p "$(dirname "$HASHCAT_WORDLIST")"
  temporary_file="${HASHCAT_WORDLIST}.download"
  trap 'rm -f "$temporary_file"' EXIT
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "$temporary_file" "$SECLISTS_WORDLIST_URL"
  test -s "$temporary_file"
  mv "$temporary_file" "$HASHCAT_WORDLIST"
fi

exec "$@"
