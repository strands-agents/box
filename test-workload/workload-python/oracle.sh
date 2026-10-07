#!/bin/bash
# The dimension's HOST oracle. It declares nothing itself: the assertions are
# `wl_checks` in case.sh, and the engine that records and scores them is
# common/workload-oracle-lib.sh. Copy verbatim into a new dimension.
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../common/workload-lib.sh"
wl_resolve_paths
# shellcheck disable=SC1090
source "$HERE/case.sh"
# shellcheck disable=SC1091
source "$HERE/../common/workload-oracle-lib.sh"
wl_oracle_main "$@"
