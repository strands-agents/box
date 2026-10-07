#!/bin/bash
# network-egress/oracle.sh — Network/egress oracle for the network-egress case.
# Thin wrapper (option A): the platform-agnostic engine lives in
# common/oracle-lib.sh; this file only declares WHAT this dimension forbids.
# A case with a bespoke oracle can replace this with a full script.
#
# Usage: oracle.sh start|stop|status|tail   (output dir from $INDET_ORACLE_DIR)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../common/oracle-lib.sh"

ORACLE_DIMENSION="network-egress"
# Forbidden destination for this dimension: the link-local / metadata range. RED only
# when a process in the box's subtree owns a connection here, attributed by ancestry.
#
# The capture filter and the socket match must describe ONE set. They did not before:
# the capture watched the whole /16 while socket enumeration looked at a single
# address, so a connection to any other link-local address could never be attributed
# and could never go RED. Change these together.
ORACLE_FORBIDDEN_FILTER="dst net 169.254.0.0/16"
ORACLE_FORBIDDEN_MATCH='->169\.254\.'

oracle_main "$@"
