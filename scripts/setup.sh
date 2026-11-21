#!/bin/bash
# Stand up the disposable admission-lab kind cluster + Kyverno PSS (enforce).
set -euo pipefail
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/config}"
LAB="${LAB:-$ROOT}"
CLUSTER_NAME="${CLUSTER_NAME:-admission-lab}"
KIND_IMAGE="${KIND_IMAGE:-kindest/node:v1.31.0}"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing $1"; }
need docker; need kind; need kubectl; need helm

docker info >/dev/null 2>&1 || die "docker daemon not running"
mkdir -p "$(dirname "$KUBECONFIG")" "$LAB/report"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "kind cluster '$CLUSTER_NAME' already exists"
else
  log "pulling $KIND_IMAGE (if needed)"
  docker pull "$KIND_IMAGE"
  log "creating kind cluster '$CLUSTER_NAME'"
  kind create cluster \
    --name "$CLUSTER_NAME" \
    --image "$KIND_IMAGE" \
    --config "$LAB/cluster/kind-config.yaml" \
    --kubeconfig "$KUBECONFIG" \
    --wait 180s
fi

# Ensure kubeconfig is the kind cluster's
kind export kubeconfig --name "$CLUSTER_NAME" --kubeconfig "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
kubectl cluster-info
kubectl wait --for=condition=Ready nodes --all --timeout=180s

log "preloading busybox images into the cluster"
docker pull busybox:1.36
docker pull busybox:latest
kind load docker-image busybox:1.36 --name "$CLUSTER_NAME" || true
kind load docker-image busybox:latest --name "$CLUSTER_NAME" || true

if kubectl get ns kyverno >/dev/null 2>&1 && helm status kyverno -n kyverno >/dev/null 2>&1; then
  log "Kyverno already installed"
else
  log "adding Kyverno helm repo"
  helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
  helm repo update kyverno >/dev/null
  log "installing Kyverno (admission controller only)"
  helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno --create-namespace \
    --values "$LAB/cluster/kyverno-values.yaml" \
    --wait --timeout 8m
fi

kubectl wait -n kyverno --for=condition=Ready pods --all --timeout=180s

if helm status kyverno-policies -n kyverno >/dev/null 2>&1; then
  log "kyverno-policies already installed"
else
  log "installing Kyverno restricted PSS policies in Enforce mode"
  # Try the chart with our values; fall back to a known-good flag set if the
  # exclude schema changed.
  if ! helm upgrade --install kyverno-policies kyverno/kyverno-policies \
      --namespace kyverno \
      --set podSecurityStandard=restricted \
      --set validationFailureAction=Enforce \
      --set failurePolicy=Fail \
      --set background=false \
      --wait --timeout 3m; then
    die "kyverno-policies helm install failed"
  fi
fi

# Exclude system namespaces from every ClusterPolicy if the chart didn't.
log "ensuring system namespaces are excluded from ClusterPolicies"
python3 - << 'PY'
import json, subprocess, sys
exclusions = ["kube-system", "kyverno", "local-path-storage"]
out = subprocess.check_output(["kubectl","get","clusterpolicy","-o","json"], text=True)
pols = json.loads(out).get("items", [])
for p in pols:
    name = p["metadata"]["name"]
    spec = p.setdefault("spec", {})
    # Skip if already has a namespace NotIn exclude covering kube-system
    def has_ns_exclude(spec):
        for ev in spec.get("rules") or []:
            pass
        match = spec.get("match") or {}
        exclude = spec.get("exclude") or {}
        # Kyverno v1: spec.rules[].exclude / spec.exclude
        candidates = [exclude]
        for rule in spec.get("rules") or []:
            candidates.append(rule.get("exclude") or {})
        for c in candidates:
            any_list = (c.get("any") or []) + (c.get("all") or [])
            # also older shape: resources.namespaces
            res = c.get("resources") or {}
            if "kube-system" in (res.get("namespaces") or []):
                return True
            for item in any_list:
                ns = ((item.get("resources") or {}).get("namespaces") or [])
                if "kube-system" in ns:
                    return True
        return False
    if has_ns_exclude(spec):
        continue
    # Patch each policy with an exclude.any for system namespaces (merge-friendly)
    patch = {
      "spec": {
        "exclude": {
          "any": [
            {"resources": {"namespaces": exclusions}}
          ]
        }
      }
    }
    # Prefer adding exclude on each rule to be compatible with newer schema
    rules = spec.get("rules") or []
    if rules:
        new_rules = []
        for r in rules:
            excl = r.get("exclude") or {}
            any_list = list(excl.get("any") or [])
            any_list.append({"resources": {"namespaces": exclusions}})
            excl["any"] = any_list
            r["exclude"] = excl
            new_rules.append(r)
        patch = {"spec": {"rules": new_rules}}
    subprocess.run(
        ["kubectl","patch","clusterpolicy",name,"--type=merge","-p",json.dumps(patch)],
        check=False,
    )
    print(f"patched exclude on {name}")
PY

log "creating test namespace"
kubectl create namespace admission-lab --dry-run=client -o yaml | kubectl apply -f -

log "setup complete"
kubectl get nodes -o wide
kubectl get pods -n kyverno -o wide
kubectl get clusterpolicy
