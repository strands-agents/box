#!/bin/bash
# Thin wrapper -> common/workload-agent-a.sh. Copy verbatim into a new dimension.
HERE="$(cd "$(dirname "$0")" && pwd)"
exec bash "$HERE/../common/workload-agent-a.sh" "$1" "$HERE"
