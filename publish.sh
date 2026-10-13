#!/usr/bin/env bash
set -euo pipefail

version="$1"
echo "new_release=true" >> "$GITHUB_OUTPUT"
echo "version=${version}" >> "$GITHUB_OUTPUT"
