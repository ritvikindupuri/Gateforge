#!/bin/bash
# K8s Admission Attack Lab — one-command orchestrator for the admission-time attack loop.
# Run from the repo root on a disposable lab host (Kali + kind).
set -euo pipefail
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ROOT="$(cd "$(dirname "$0")" && pwd)"
export KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/config}"
export LAB="${LAB:-$ROOT}"
export DEBIAN_FRONTEND=noninteractive

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || return 1; }

log "ensuring Kali tools (peirates, trivy, nmap, nuclei)"
need nmap || apt-get install -y -qq nmap
need nuclei || apt-get install -y -qq nuclei
need peirates || apt-get install -y -qq peirates
need trivy || apt-get install -y -qq trivy
need docker && need kind && need kubectl && need helm

if ! kind get clusters 2>/dev/null | grep -qx admission-lab; then
  log "kind cluster missing — running setup.sh"
  bash "$LAB/scripts/setup.sh"
else
  kind export kubeconfig --name admission-lab --kubeconfig "$KUBECONFIG"
  log "kind cluster admission-lab already exists"
fi

log "phase 2: multi-engine admission battery + generated policies"
python3 -u "$LAB/scripts/run_phase2.py"

log "kali-tools stage: nmap, nuclei, peirates, trivy, feed-into-loop"
python3 -u "$LAB/scripts/run_kali_stage.py"

log "done. reports:"
log "  $LAB/report/scorecard.html"
log "  $LAB/report/kali-tools/"
log "  $LAB/report/phase2-matrix.txt"
