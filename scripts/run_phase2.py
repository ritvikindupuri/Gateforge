#!/usr/bin/env python3
"""K8s Admission-Time Attack Simulator — Phase 2

Closed loop:
  1. Fire the same attack battery at Kyverno, OPA Gatekeeper, and built-in PSA
     (one engine at a time, to fit a 4 GiB kind node).
  2. Treat stock-engine misses as findings.
  3. Auto-generate a Kyverno ValidatingPolicy for each gap.
  4. Apply the policy and re-run the attack to prove the gap is closed.
  5. Re-run the full battery under Kyverno + generated policies.
  6. Write a side-by-side matrix and a single-file HTML report.

Policy/admission testing only. No runtime exploitation.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = Path(os.environ.get("LAB", str(REPO)))
MANIFESTS = LAB / "manifests"
REPORT = LAB / "report"
SUGGESTED = LAB / "policies" / "suggested"
GK_DIR = LAB / "cluster" / "gatekeeper"
NS = "admission-lab"
KUBECONFIG = os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))
ENV = {
    **os.environ,
    "KUBECONFIG": KUBECONFIG,
    "PATH": "/usr/local/bin:" + os.environ.get("PATH", ""),
}
LIBRARY = (
    "https://raw.githubusercontent.com/open-policy-agent/"
    "gatekeeper-library/master/library/pod-security-policy"
)
EXCLUDED_NS = ["kube-system", "gatekeeper-system", "kyverno", "local-path-storage"]

# Existing 8 + broadened battery. "compliant" is the control case, not an attack.
SCENARIOS = [
    {"id": "privileged", "file": "01-privileged.yaml", "title": "Privileged container", "technique": "securityContext.privileged=true", "attack": True, "wait_running": False},
    {"id": "hostpath", "file": "02-hostpath.yaml", "title": "hostPath mount of /etc", "technique": "volumes.hostPath.path=/etc", "attack": True, "wait_running": False},
    {"id": "hostnetwork", "file": "03-hostnetwork.yaml", "title": "hostNetwork pod", "technique": "spec.hostNetwork=true", "attack": True, "wait_running": False},
    {"id": "run-as-root", "file": "04-run-as-root.yaml", "title": "Explicit runAsUser 0", "technique": "securityContext.runAsUser=0", "attack": True, "wait_running": False},
    {"id": "docker-sock", "file": "05-docker-sock.yaml", "title": "Docker socket hostPath", "technique": "hostPath /var/run/docker.sock", "attack": True, "wait_running": False},
    {"id": "latest-tag", "file": "06-latest-tag.yaml", "title": "Mutable :latest image tag", "technique": "image: busybox:latest (otherwise hardened)", "attack": True, "wait_running": False, "gap_candidate": True},
    {"id": "no-limits", "file": "07-no-limits.yaml", "title": "No CPU/memory limits", "technique": "no resources.limits (otherwise hardened)", "attack": True, "wait_running": False, "gap_candidate": True},
    {"id": "compliant", "file": "08-compliant.yaml", "title": "Restricted-compliant workload", "technique": "non-root, drop ALL, pinned tag, limits, read-only rootfs", "attack": False, "wait_running": True},
    {"id": "hostpid", "file": "09-hostpid.yaml", "title": "hostPID pod", "technique": "spec.hostPID=true (otherwise hardened)", "attack": True, "wait_running": False},
    {"id": "hostipc", "file": "10-hostipc.yaml", "title": "hostIPC pod", "technique": "spec.hostIPC=true (otherwise hardened)", "attack": True, "wait_running": False},
    {"id": "cap-sys-admin", "file": "11-cap-sys-admin.yaml", "title": "Added CAP_SYS_ADMIN", "technique": "capabilities.add=[SYS_ADMIN]", "attack": True, "wait_running": False},
    {"id": "cap-net-raw", "file": "12-cap-net-raw.yaml", "title": "Added CAP_NET_RAW", "technique": "capabilities.add=[NET_RAW]", "attack": True, "wait_running": False},
    {"id": "untrusted-registry", "file": "13-untrusted-registry.yaml", "title": "Untrusted image registry", "technique": "image from untrusted.example.invalid", "attack": True, "wait_running": False, "gap_candidate": True},
    {"id": "writable-rootfs", "file": "14-writable-rootfs.yaml", "title": "Writable root filesystem", "technique": "readOnlyRootFilesystem=false (otherwise hardened)", "attack": True, "wait_running": False, "gap_candidate": True},
]

GK_TEMPLATES = [
    "privileged-containers",
    "host-namespaces",
    "host-network-ports",
    "host-filesystem",
    "capabilities",
    "allow-privilege-escalation",
    "read-only-root-filesystem",
    "users",
    "volumes",
    "seccompv2",
]
GK_CONSTRAINTS = [
    "privileged-containers/samples/psp-privileged-container/constraint.yaml",
    "host-namespaces/samples/psp-host-namespace/constraint.yaml",
    "host-network-ports/samples/psp-host-network-ports/constraint.yaml",
    "host-network-ports/samples/host-network-ports/constraint.yaml",
    "host-filesystem/samples/no-host-paths/constraint.yaml",
    "capabilities/samples/psp-capabilities-restricted/constraint.yaml",
    "allow-privilege-escalation/samples/psp-allow-privilege-escalation-container/constraint.yaml",
    "read-only-root-filesystem/samples/psp-readonlyrootfilesystem/constraint.yaml",
    "read-only-root-filesystem/samples/read-only-root-filesystem/constraint.yaml",
    "users/samples/psp-pods-allowed-user-ranges/constraint.yaml",
    "volumes/samples/psp-volume-types/constraint.yaml",
    "seccompv2/samples/psp-seccomp-restricted/constraint.yaml",
]


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(args, input_text=None, timeout=180, check=False):
    r = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, env=ENV)
    if check and r.returncode != 0:
        raise RuntimeError(f"{args} failed ({r.returncode}): {r.stdout}\n{r.stderr}")
    return r.returncode, r.stdout, r.stderr


def kubectl(args, timeout=180, input_text=None, check=False):
    return sh(["kubectl", *args], input_text=input_text, timeout=timeout, check=check)


def helm(args, timeout=300, check=False):
    return sh(["helm", *args], timeout=timeout, check=check)


def curl_get(url: str, dest: Path, timeout=90) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 20:
        return True
    try:
        rc, out, err = sh(["curl", "-fsSL", "--retry", "2", "--retry-delay", "2", "--connect-timeout", "20",
                           "-o", str(dest), url], timeout=timeout)
    except subprocess.TimeoutExpired:
        return dest.exists() and dest.stat().st_size > 20
    if rc != 0 or not dest.exists() or dest.stat().st_size < 20:
        if dest.exists() and dest.stat().st_size < 20:
            dest.unlink()
        return dest.exists() and dest.stat().st_size > 20
    return True


# ---------------------------------------------------------------------------
# Admission apply + parse
# ---------------------------------------------------------------------------

def parse_policies(engine: str, text: str) -> list[str]:
    names: list[str] = []
    if engine.startswith("kyverno"):
        for m in re.finditer(r"Policy\s+([a-z0-9-]+)\s+failed:", text):
            names.append(m.group(1))
        for m in re.finditer(
            r"(disallow-[a-z0-9-]+|require-[a-z0-9-]+|restrict-[a-z0-9-]+|deny-[a-z0-9-]+)",
            text,
        ):
            names.append(m.group(1))
    elif engine == "gatekeeper":
        for m in re.finditer(r"denied by ([a-z0-9-]+)", text, re.I):
            names.append(m.group(1))
        for m in re.finditer(r"\[([a-z0-9-]+)\]", text):
            names.append(m.group(1))
    elif engine == "psa":
        # "violates PodSecurity "restricted:latest": privileged (...), hostPath (...)"
        if "PodSecurity" in text:
            names.append("psa-restricted")
            for m in re.finditer(
                r"(privileged|hostPath|hostNetwork|hostPID|hostIPC|runAsNonRoot|runAsUser|allowPrivilegeEscalation|capabilities|seccompProfile|volume types|procMount|seLinux|appArmor|sysctls|windowsHostProcess)",
                text,
            ):
                names.append(m.group(1))
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def pod_name(path: Path) -> str:
    rc, out, _ = kubectl(["apply", "--dry-run=client", "-f", str(path), "-o", "jsonpath={.metadata.name}"])
    return out.strip() or path.stem


def wait_running(name: str, timeout=90) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        rc, out, err = kubectl(["-n", NS, "get", "pod", name, "-o", "jsonpath={.status.phase}"])
        last = (out or err or "").strip()
        if last == "Running":
            return True, last
        if last in {"Failed", "Succeeded"}:
            return False, last
        time.sleep(2)
    return False, f"timeout phase={last}"


def apply_one(engine: str, s: dict) -> dict:
    path = MANIFESTS / s["file"]
    name = pod_name(path)
    kubectl(["-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=true"], timeout=60)
    t0 = time.time()
    rc, out, err = kubectl(["apply", "-f", str(path)], timeout=60)
    text = ((out or "") + (err or "")).strip()
    elapsed_ms = int((time.time() - t0) * 1000)
    admitted = rc == 0
    result = "ADMITTED" if admitted else "BLOCKED"
    policies = parse_policies(engine, text) if not admitted else []
    running = None
    run_detail = ""
    if admitted and s.get("wait_running"):
        ok, run_detail = wait_running(name, timeout=90)
        running = ok
    if admitted:
        kubectl(["-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=false"], timeout=30)
    return {
        "id": s["id"],
        "title": s["title"],
        "technique": s["technique"],
        "attack": s["attack"],
        "result": result,
        "policies": policies,
        "pod_ran": running,
        "latency_ms": elapsed_ms,
        "message": text[:1800],
        "run_detail": (run_detail or "")[:400],
    }


def run_battery(engine: str) -> list[dict]:
    ensure_namespace()
    results = []
    for s in SCENARIOS:
        log(f"  {engine}: {s['id']} ...")
        try:
            r = apply_one(engine, s)
        except subprocess.TimeoutExpired:
            r = {
                "id": s["id"], "title": s["title"], "technique": s["technique"],
                "attack": s["attack"], "result": "ERROR", "policies": [],
                "pod_ran": None, "latency_ms": None, "message": "kubectl timed out", "run_detail": "",
            }
        results.append(r)
        log(f"    {r['result']:9}  gates={r['policies']}")
    return results


def coverage(results: list[dict]) -> dict:
    attacks = [r for r in results if r["attack"]]
    blocked = sum(1 for r in attacks if r["result"] == "BLOCKED")
    admitted = sum(1 for r in attacks if r["result"] == "ADMITTED")
    control = next((r for r in results if not r["attack"]), None)
    return {
        "attacks": len(attacks),
        "blocked": blocked,
        "admitted": admitted,
        "coverage_pct": round(100.0 * blocked / len(attacks), 1) if attacks else 0.0,
        "gaps": [r["id"] for r in attacks if r["result"] == "ADMITTED"],
        "compliant_admitted": bool(control and control["result"] == "ADMITTED"),
        "compliant_ran": bool(control and control.get("pod_ran")),
    }


# ---------------------------------------------------------------------------
# Cluster helpers
# ---------------------------------------------------------------------------

def ensure_namespace() -> None:
    manifest = f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"
    kubectl(["apply", "-f", "-"], input_text=manifest)
    # Make sure leftover PSA labels are cleared unless the PSA engine set them.
    # Callers that need PSA will re-label.


def clear_psa_labels() -> None:
    for key in (
        "pod-security.kubernetes.io/enforce",
        "pod-security.kubernetes.io/enforce-version",
        "pod-security.kubernetes.io/audit",
        "pod-security.kubernetes.io/audit-version",
        "pod-security.kubernetes.io/warn",
        "pod-security.kubernetes.io/warn-version",
    ):
        kubectl(["label", "ns", NS, f"{key}-", "--overwrite"])


def wait_gone(kind: str, timeout=180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out, _ = kubectl(["get", kind, "-o", "name"])
        if rc != 0 or not out.strip():
            return
        time.sleep(2)


def webhook_names() -> list[str]:
    names = []
    for kind in ("validatingwebhookconfiguration", "mutatingwebhookconfiguration"):
        rc, out, _ = kubectl(["get", kind, "-o", "name"])
        names.extend(out.split())
    return names


def wait_no_webhooks(substrs, timeout=180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        left = [n for n in webhook_names() if any(s in n.lower() for s in substrs)]
        if not left:
            return
        time.sleep(3)
    left = [n for n in webhook_names() if any(s in n.lower() for s in substrs)]
    if left:
        log(f"WARNING: webhooks still present: {left}")
        for n in left:
            kubectl(["delete", n, "--ignore-not-found", "--wait=false"])


def uninstall_kyverno() -> None:
    log("uninstalling Kyverno")
    helm(["uninstall", "kyverno-policies", "-n", "kyverno", "--wait", "--timeout", "3m"], timeout=200)
    helm(["uninstall", "kyverno", "-n", "kyverno", "--wait", "--timeout", "3m"], timeout=200)
    kubectl(["delete", "validatingpolicy", "--all", "--ignore-not-found"])
    kubectl(["delete", "ns", "kyverno", "--ignore-not-found", "--timeout=180s"], timeout=200)
    rc, out, _ = kubectl(["get", "validatingwebhookconfiguration,mutatingwebhookconfiguration", "-o", "name"])
    for n in out.split():
        if "kyverno" in n.lower():
            kubectl(["delete", n, "--ignore-not-found"])
    wait_no_webhooks(["kyverno"])
    log("Kyverno gone")


def uninstall_gatekeeper() -> None:
    log("uninstalling Gatekeeper")
    # Delete constraints first so uninstall isn't blocked.
    rc, out, _ = kubectl(["api-resources", "--api-group=constraints.gatekeeper.sh", "-o", "name"])
    for kind in out.split():
        kubectl(["delete", kind, "--all", "--ignore-not-found"])
    helm(["uninstall", "gatekeeper", "-n", "gatekeeper-system", "--wait", "--timeout", "3m"], timeout=200)
    kubectl(["delete", "ns", "gatekeeper-system", "--ignore-not-found", "--timeout=180s"], timeout=200)
    rc, out, _ = kubectl(["get", "validatingwebhookconfiguration,mutatingwebhookconfiguration", "-o", "name"])
    for n in out.split():
        if "gatekeeper" in n.lower():
            kubectl(["delete", n, "--ignore-not-found"])
    wait_no_webhooks(["gatekeeper"])
    log("Gatekeeper gone")


def teardown_engines(keep: str | None = None) -> None:
    """Remove every admission engine except optionally `keep`."""
    clear_psa_labels()
    if keep != "kyverno":
        rc, out, _ = helm(["list", "-n", "kyverno", "-q"])
        if "kyverno" in (out or ""):
            uninstall_kyverno()
        else:
            # leftover ns / webhooks
            rc, out, _ = kubectl(["get", "ns", "kyverno", "--ignore-not-found", "-o", "name"])
            if out.strip():
                uninstall_kyverno()
            wait_no_webhooks(["kyverno"])
    if keep != "gatekeeper":
        rc, out, _ = helm(["list", "-n", "gatekeeper-system", "-q"])
        if "gatekeeper" in (out or ""):
            uninstall_gatekeeper()
        else:
            rc, out, _ = kubectl(["get", "ns", "gatekeeper-system", "--ignore-not-found", "-o", "name"])
            if out.strip():
                uninstall_gatekeeper()
            wait_no_webhooks(["gatekeeper"])


def install_kyverno(extra_policies: list[Path] | None = None) -> None:
    log("installing Kyverno + restricted PSS")
    helm(["repo", "add", "kyverno", "https://kyverno.github.io/kyverno/"])
    helm(["repo", "update", "kyverno"], timeout=120)
    helm(
        [
            "upgrade", "--install", "kyverno", "kyverno/kyverno",
            "--namespace", "kyverno", "--create-namespace",
            "--values", str(LAB / "cluster" / "kyverno-values.yaml"),
            "--wait", "--timeout", "8m",
        ],
        timeout=540,
        check=True,
    )
    kubectl(["wait", "-n", "kyverno", "--for=condition=Ready", "pods", "--all", "--timeout=180s"], check=True)
    helm(
        [
            "upgrade", "--install", "kyverno-policies", "kyverno/kyverno-policies",
            "--namespace", "kyverno",
            "--set", "podSecurityStandard=restricted",
            "--set", "validationFailureAction=Enforce",
            "--set", "failurePolicy=Fail",
            "--set", "background=false",
            "--wait", "--timeout", "3m",
        ],
        timeout=240,
        check=True,
    )
    # wait until at least one ValidatingPolicy is Ready
    for _ in range(30):
        rc, out, _ = kubectl(["get", "validatingpolicy", "--no-headers"])
        if rc == 0 and "true" in out.lower() or (out and len(out.splitlines()) >= 5):
            break
        time.sleep(2)
    if extra_policies:
        for p in extra_policies:
            log(f"applying suggested policy {p.name}")
            kubectl(["apply", "-f", str(p)], check=True)
        time.sleep(3)
    log("Kyverno ready")


def install_gatekeeper() -> None:
    log("installing OPA Gatekeeper (1 replica, audit off, no mutation)")
    helm(["repo", "add", "gatekeeper", "https://open-policy-agent.github.io/gatekeeper/charts"])
    helm(["repo", "update", "gatekeeper"], timeout=120)
    # Try a low-RAM value set; fall back if a key is rejected.
    attempts = [
        [
            "--set", "replicas=1",
            "--set", "audit.replicas=0",
            "--set", "disableMutation=true",
            "--set", "controllerManager.resources.requests.memory=128Mi",
            "--set", "controllerManager.resources.limits.memory=384Mi",
            "--set", "controllerManager.exemptNamespaces={kube-system,gatekeeper-system,local-path-storage}",
        ],
        [
            "--set", "replicas=1",
            "--set", "auditInterval=0",
            "--set", "disableMutation=true",
        ],
        ["--set", "replicas=1"],
    ]
    last_err = ""
    ok = False
    for extra in attempts:
        args = [
            "upgrade", "--install", "gatekeeper", "gatekeeper/gatekeeper",
            "--namespace", "gatekeeper-system", "--create-namespace",
            "--wait", "--timeout", "8m", *extra,
        ]
        rc, out, err = helm(args, timeout=540)
        if rc == 0:
            ok = True
            break
        last_err = (out or "") + (err or "")
        log(f"Gatekeeper helm attempt failed, trying fallback:\n{last_err[-400:]}")
    if not ok:
        raise RuntimeError(f"Gatekeeper install failed: {last_err[-1500:]}")
    kubectl(["wait", "-n", "gatekeeper-system", "--for=condition=Ready", "pods", "--all", "--timeout=240s"], timeout=250)
    GK_DIR.mkdir(parents=True, exist_ok=True)
    applied_templates = []
    for name in GK_TEMPLATES:
        dest = GK_DIR / f"template-{name}.yaml"
        url = f"{LIBRARY}/{name}/template.yaml"
        log(f"fetching Gatekeeper template {name}")
        if not curl_get(url, dest):
            log(f"WARNING: could not fetch template {name}")
            continue
        rc, out, err = kubectl(["apply", "-f", str(dest)])
        if rc != 0:
            log(f"WARNING: apply template {name} failed: {(err or out)[-300:]}")
        else:
            applied_templates.append(name)
    # Wait for constraint CRDs
    time.sleep(5)
    applied_c = []
    for rel in GK_CONSTRAINTS:
        dest = GK_DIR / ("constraint-" + rel.replace("/", "_"))
        url = f"{LIBRARY}/{rel}"
        if not curl_get(url, dest):
            continue
        # Patch in exclusions + deny
        text = dest.read_text()
        if "excludedNamespaces" not in text:
            # insert under spec.match
            if "spec:\n  match:" in text:
                text = text.replace(
                    "spec:\n  match:",
                    "spec:\n  enforcementAction: deny\n  match:\n    excludedNamespaces:\n"
                    + "".join(f"    - {n}\n" for n in EXCLUDED_NS),
                    1,
                )
            dest.write_text(text)
        rc, out, err = kubectl(["apply", "-f", str(dest)])
        if rc == 0:
            applied_c.append(rel)
            log(f"applied constraint {rel}")
        else:
            log(f"constraint skip/fail {rel}: {(err or out)[-250:]}")
    if not applied_c:
        raise RuntimeError("no Gatekeeper PSP constraints could be applied")
    log(f"Gatekeeper ready with {len(applied_templates)} templates, {len(applied_c)} constraints")
    # Give the webhook a moment to start enforcing new constraints
    time.sleep(8)
    kubectl(["get", "constraints"] if False else ["get", "constrainttemplate"])
    rc, out, err = sh(["kubectl", "get", "constraints"], timeout=30)
    log((out or err or "")[:800])


def install_psa() -> None:
    log("enabling built-in Pod Security Admission enforce=restricted")
    ensure_namespace()
    kubectl(
        [
            "label", "ns", NS, "--overwrite",
            "pod-security.kubernetes.io/enforce=restricted",
            "pod-security.kubernetes.io/enforce-version=latest",
            "pod-security.kubernetes.io/audit=restricted",
            "pod-security.kubernetes.io/audit-version=latest",
            "pod-security.kubernetes.io/warn=restricted",
            "pod-security.kubernetes.io/warn-version=latest",
        ],
        check=True,
    )
    log("PSA labels applied")


# ---------------------------------------------------------------------------
# Suggested Kyverno policies (gap closers)
# ---------------------------------------------------------------------------

POLICY_TEMPLATES = {
    "latest-tag": {
        "name": "deny-latest-tag",
        "title": "Deny mutable :latest (or untagged) images",
        "message": "Image tags must be pinned. ':latest' and untagged images are not allowed.",
        "expression": """object.spec.containers.all(c,
        c.image.contains("@sha256:") || (c.image.contains(":") && !c.image.endsWith(":latest")))
        && (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
        c.image.contains("@sha256:") || (c.image.contains(":") && !c.image.endsWith(":latest"))))""",
    },
    "no-limits": {
        "name": "require-resource-limits",
        "title": "Require CPU and memory limits",
        "message": "Every container must set resources.limits.cpu and resources.limits.memory.",
        "expression": """object.spec.containers.all(c,
        has(c.resources) && has(c.resources.limits)
        && has(c.resources.limits.cpu) && has(c.resources.limits.memory))
        && (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
        has(c.resources) && has(c.resources.limits)
        && has(c.resources.limits.cpu) && has(c.resources.limits.memory)))""",
    },
    "untrusted-registry": {
        "name": "restrict-image-registries",
        "title": "Allow only docker.io / short-name official images",
        "message": "Images must come from docker.io or use a short name (no third-party registry host).",
        "expression": """object.spec.containers.all(c,
        c.image.startsWith("docker.io/") || !c.image.contains("/") || !c.image.split("/")[0].contains("."))
        && (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
        c.image.startsWith("docker.io/") || !c.image.contains("/") || !c.image.split("/")[0].contains(".")))""",
    },
    "writable-rootfs": {
        "name": "require-readonly-rootfs",
        "title": "Require read-only root filesystem",
        "message": "Every container must set securityContext.readOnlyRootFilesystem=true.",
        "expression": """object.spec.containers.all(c,
        has(c.securityContext) && has(c.securityContext.readOnlyRootFilesystem)
        && c.securityContext.readOnlyRootFilesystem == true)
        && (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
        has(c.securityContext) && has(c.securityContext.readOnlyRootFilesystem)
        && c.securityContext.readOnlyRootFilesystem == true))""",
    },
}


def render_policy(gap_id: str) -> tuple[str, str]:
    t = POLICY_TEMPLATES[gap_id]
    yaml = f"""apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: {t['name']}
  labels:
    lab.component: suggested-policy
    lab.closes: {gap_id}
  annotations:
    policies.kyverno.io/title: {t['title']}
    policies.kyverno.io/category: Admission Lab suggested
    policies.kyverno.io/description: Auto-generated to close the '{gap_id}' gap found by the admission-time attack battery.
spec:
  failurePolicy: Fail
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >-
        {t['expression']}
      message: {t['message']}
"""
    return t["name"], yaml


def generate_and_prove(gaps: list[str], kyverno_results: list[dict]) -> list[dict]:
    """Generate a policy for each Kyverno stock gap, apply it, re-run the attack."""
    SUGGESTED.mkdir(parents=True, exist_ok=True)
    proofs = []
    for gap_id in gaps:
        if gap_id not in POLICY_TEMPLATES:
            log(f"no generator for gap {gap_id}; skipping")
            proofs.append({"id": gap_id, "generated": False, "reason": "no template", "proved": False})
            continue
        name, yaml = render_policy(gap_id)
        path = SUGGESTED / f"{name}.yaml"
        path.write_text(yaml)
        log(f"generated {path}")
        # Baseline: confirm still admitted under stock PSS (no suggested policies yet, or others already on)
        # Apply this policy, wait, re-run the matching manifest.
        rc, out, err = kubectl(["apply", "-f", str(path)])
        if rc != 0:
            proofs.append({
                "id": gap_id, "policy": name, "path": str(path),
                "generated": True, "applied": False, "apply_error": (err or out)[-500],
                "before": "ADMITTED", "after": "ERROR", "proved": False,
            })
            continue
        time.sleep(4)
        scenario = next(s for s in SCENARIOS if s["id"] == gap_id)
        after = apply_one("kyverno+fixes", scenario)
        proved = after["result"] == "BLOCKED" and name in after["policies"] or after["result"] == "BLOCKED"
        proofs.append({
            "id": gap_id,
            "policy": name,
            "path": str(path),
            "title": POLICY_TEMPLATES[gap_id]["title"],
            "generated": True,
            "applied": True,
            "before": "ADMITTED",
            "after": after["result"],
            "policies": after["policies"],
            "message": after["message"][:800],
            "proved": proved,
        })
        log(f"  re-run {gap_id}: {after['result']} policies={after['policies']} proved={proved}")
    return proofs


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

ENGINE_LABELS = {
    "kyverno": "Kyverno PSS",
    "gatekeeper": "Gatekeeper PSP",
    "psa": "Built-in PSA",
    "kyverno+fixes": "Kyverno + generated",
}


def render_text_matrix(by_engine: dict, cov: dict, proofs: list[dict], generated_at: str) -> str:
    engines = [e for e in ("kyverno", "gatekeeper", "psa", "kyverno+fixes") if e in by_engine]
    ids = [s["id"] for s in SCENARIOS]
    idw = max(len("SCENARIO"), max(len(i) for i in ids))
    ew = 16
    header = "SCENARIO".ljust(idw) + "".join(ENGINE_LABELS[e][:ew].center(ew) for e in engines)
    lines = [
        "K8s ADMISSION-TIME ATTACK SIMULATOR — PHASE 2  (policy gate only)",
        f"Generated (America/Indianapolis): {generated_at}",
        "Same battery, three stock engines, then Kyverno + auto-generated gap closers.",
        "",
        header,
        "-" * len(header),
    ]
    for s in SCENARIOS:
        row = s["id"].ljust(idw)
        for e in engines:
            r = next((x for x in by_engine[e] if x["id"] == s["id"]), None)
            cell = r["result"] if r else "?"
            row += cell.center(ew)
        if not s["attack"]:
            row += "  (control)"
        lines.append(row)
    lines.append("-" * len(header))
    lines.append("")
    lines.append("Coverage = attacks blocked / attack scenarios (control excluded).")
    for e in engines:
        c = cov[e]
        lines.append(
            f"  {ENGINE_LABELS[e]}: {c['coverage_pct']}%  ({c['blocked']}/{c['attacks']} blocked)"
            f"  gaps={c['gaps'] or 'none'}"
            f"  compliant={'ADMITTED' if c['compliant_admitted'] else 'BLOCKED'}"
            + ("; Running" if c["compliant_ran"] else "")
        )
    lines.append("")
    lines.append("Closed loop (finding → generated Kyverno policy → re-run):")
    if not proofs:
        lines.append("  (no gaps to close)")
    for p in proofs:
        if not p.get("generated"):
            lines.append(f"  - {p['id']}: no generator ({p.get('reason','')})")
            continue
        status = "PROVED CLOSED" if p.get("proved") else "NOT PROVED"
        lines.append(
            f"  - {p['id']}: {p.get('before')} → policy {p.get('policy')} → {p.get('after')}  [{status}]"
        )
    lines.append("")
    lines.append("Rerun:  export PATH=/usr/local/bin:$PATH")
    lines.append("        python3 $LAB/scripts/run_phase2.py")
    return "\n".join(lines) + "\n"


def render_html(by_engine: dict, cov: dict, proofs: list[dict], generated_at: str, prior_art: str) -> str:
    engines = [e for e in ("kyverno", "gatekeeper", "psa", "kyverno+fixes") if e in by_engine]

    def cell(engine, sid, attack):
        r = next((x for x in by_engine[engine] if x["id"] == sid), None)
        if not r:
            return '<td class="unk">?</td>'
        result = r["result"]
        cls = "block" if result == "BLOCKED" else "admit" if result == "ADMITTED" else "err"
        if not attack and result == "ADMITTED":
            cls = "ok"
        if not attack and result == "BLOCKED":
            cls = "fp"
        title = ", ".join(r.get("policies") or []) or result
        return f'<td class="{cls}" title="{html_esc(title)}">{html_esc(result)}</td>'

    rows = []
    for s in SCENARIOS:
        kind = "control" if not s["attack"] else "attack"
        tds = "".join(cell(e, s["id"], s["attack"]) for e in engines)
        rows.append(
            f'<tr class="{kind}"><th>{html_esc(s["id"])}</th>'
            f'<td class="tech">{html_esc(s["technique"])}</td>{tds}</tr>'
        )
    cov_cards = []
    for e in engines:
        c = cov[e]
        cov_cards.append(
            f'<div class="card"><h3>{html_esc(ENGINE_LABELS[e])}</h3>'
            f'<div class="pct">{c["coverage_pct"]}%</div>'
            f'<p>{c["blocked"]}/{c["attacks"]} attacks blocked</p>'
            f'<p>Gaps: {html_esc(", ".join(c["gaps"]) if c["gaps"] else "none")}</p>'
            f'<p>Compliant control: {"admitted" if c["compliant_admitted"] else "BLOCKED (false positive)"}'
            f'{" and Running" if c["compliant_ran"] else ""}</p></div>'
        )
    loop_rows = []
    for p in proofs:
        proved = "PROVED CLOSED" if p.get("proved") else "NOT PROVED"
        cls = "proved" if p.get("proved") else "failed"
        loop_rows.append(
            f'<tr class="{cls}"><td>{html_esc(p["id"])}</td>'
            f'<td>{html_esc(p.get("before", "—"))}</td>'
            f'<td><code>{html_esc(p.get("policy") or p.get("reason") or "—")}</code></td>'
            f'<td>{html_esc(p.get("after", "—"))}</td>'
            f'<td class="{cls}">{proved}</td></tr>'
        )
    proved_n = sum(1 for p in proofs if p.get("proved"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>K8s Admission-Time Attack Simulator — Phase 2</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a222b; --line:#2b3642; --text:#e8eef4; --muted:#9aa8b6;
          --block:#3dd68c; --admit:#f0b429; --ok:#7aa2f7; --fp:#f7768e; --err:#c0caf5; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.45 system-ui, sans-serif; background:var(--bg); color:var(--text); }}
  main {{ max-width:1100px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:1.6rem; margin:0 0 .3rem; }}
  h2 {{ font-size:1.15rem; margin:2rem 0 .6rem; }}
  .sub {{ color:var(--muted); margin-bottom:1.4rem; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
  .card h3 {{ margin:0 0 .4rem; font-size:.95rem; color:var(--muted); font-weight:600; }}
  .pct {{ font-size:2rem; font-weight:700; }}
  .card p {{ margin:.25rem 0 0; color:var(--muted); font-size:.9rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); }}
  th, td {{ padding:.45rem .6rem; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }}
  thead th {{ font-size:.8rem; letter-spacing:.04em; color:var(--muted); text-transform:uppercase; }}
  td.tech {{ color:var(--muted); font-size:.85rem; }}
  td.block {{ color:var(--block); font-weight:650; }}
  td.admit {{ color:var(--admit); font-weight:650; }}
  td.ok {{ color:var(--ok); font-weight:650; }}
  td.fp, td.failed {{ color:var(--fp); font-weight:650; }}
  tr.control th {{ color:var(--ok); }}
  .proved {{ color:var(--block); font-weight:650; }}
  code {{ font:13px/1.4 ui-monospace,monospace; background:#0c1014; padding:1px 5px; border-radius:4px; }}
  pre {{ background:#0c1014; border:1px solid var(--line); padding:12px 14px; overflow:auto; border-radius:8px; font:12.5px/1.4 ui-monospace,monospace; }}
  .note {{ color:var(--muted); font-size:.92rem; }}
</style>
</head>
<body>
<main>
  <h1>K8s Admission-Time Attack Simulator</h1>
  <p class="sub">Phase 2 closed loop &mdash; {html_esc(generated_at)} (America/Indianapolis). Policy gate only; no runtime exploitation.</p>

  <h2>Coverage by engine</h2>
  <div class="cards">{''.join(cov_cards)}</div>

  <h2>Side-by-side matrix</h2>
  <p class="note">Same 14 manifests, one engine at a time. BLOCKED is a catch on an attack; the compliant control should stay ADMITTED.</p>
  <table>
    <thead><tr><th>Scenario</th><th>Technique</th>{''.join(f'<th>{html_esc(ENGINE_LABELS[e])}</th>' for e in engines)}</tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  <h2>Closed loop</h2>
  <p class="note">Findings the stock engines missed were turned into Kyverno ValidatingPolicies, applied, and the original attack was re-run. {proved_n}/{len(proofs)} gap(s) proved closed.</p>
  <table>
    <thead><tr><th>Finding</th><th>Before</th><th>Generated policy</th><th>Re-run</th><th>Status</th></tr></thead>
    <tbody>{''.join(loop_rows)}</tbody>
  </table>

  <h2>Prior art (honest)</h2>
  <p class="note">{html_esc(prior_art)}</p>

  <h2>Rerun</h2>
  <pre>export PATH=/usr/local/bin:$PATH KUBECONFIG=/root/.kube/config
python3 $LAB/scripts/run_phase2.py</pre>
  <p class="note">Lab path: $LAB &mdash; kind cluster admission-lab, disposable.</p>
</main>
</body>
</html>
"""


def html_esc(s: str) -> str:
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


PRIOR_ART = (
    "Pieces of this exist, but not this loop as a packaged tool. kube-hunter and peirates "
    "probe or attack a cluster and stop at findings. Kubescape and Polaris scan posture and "
    "do not fire a live admission battery. Kyverno Chainsaw tests policies you already wrote; "
    "Policy Reporter visualizes results. The closest cousins are IronClaw `--emit-policy` and "
    "Valqore's generate_policy, which emit Kyverno/Gatekeeper YAML from static scan findings, "
    "and blog-level K8sGPT pipelines that draft policies and dry-run them with the Kyverno CLI. "
    "None of those run the same attack manifests against Kyverno, Gatekeeper, and built-in PSA, "
    "then auto-generate a policy for what was admitted and re-run the attack on the live webhook "
    "to prove the gap closed. That closed loop is the novel part of this lab."
)


def write_reports(by_engine, proofs, generated_at: str) -> dict:
    REPORT.mkdir(parents=True, exist_ok=True)
    cov = {e: coverage(rs) for e, rs in by_engine.items()}
    payload = {
        "generated": generated_at,
        "timezone": "America/Indianapolis",
        "cluster": "kind-admission-lab",
        "focus": "admission-time policy enforcement (not runtime detection)",
        "engines": {e: {"results": by_engine[e], "coverage": cov[e]} for e in by_engine},
        "closed_loop": proofs,
        "prior_art": PRIOR_ART,
    }
    (REPORT / "phase2-matrix.json").write_text(json.dumps(payload, indent=2) + "\n")
    text = render_text_matrix(by_engine, cov, proofs, generated_at)
    (REPORT / "phase2-matrix.txt").write_text(text)
    (REPORT / "scorecard.html").write_text(render_html(by_engine, cov, proofs, generated_at, PRIOR_ART))
    # Also leave a stable phase-1-compatible name.
    (REPORT / "index.html").write_text((REPORT / "scorecard.html").read_text())
    return cov


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    SUGGESTED.mkdir(parents=True, exist_ok=True)
    ensure_namespace()
    by_engine: dict[str, list[dict]] = {}

    # 1. Kyverno stock (already installed after phase 1; reinstall if missing)
    log("===== ENGINE 1/3: Kyverno restricted PSS =====")
    teardown_engines(keep="kyverno")
    rc, out, _ = kubectl(["-n", "kyverno", "get", "pods", "--no-headers"])
    if rc != 0 or "Running" not in (out or ""):
        install_kyverno()
    else:
        log("Kyverno already running; using existing install")
    by_engine["kyverno"] = run_battery("kyverno")

    # 2. Gatekeeper
    log("===== ENGINE 2/3: OPA Gatekeeper PSP library =====")
    teardown_engines()
    install_gatekeeper()
    by_engine["gatekeeper"] = run_battery("gatekeeper")

    # 3. Built-in PSA
    log("===== ENGINE 3/3: built-in Pod Security Admission =====")
    teardown_engines()
    install_psa()
    by_engine["psa"] = run_battery("psa")
    clear_psa_labels()

    # Gaps = attacks stock Kyverno admitted (the engine we can generate policies for).
    kyverno_gaps = [
        r["id"] for r in by_engine["kyverno"]
        if r["attack"] and r["result"] == "ADMITTED"
    ]
    log(f"Kyverno stock gaps: {kyverno_gaps}")

    # 4. Closed loop: reinstall Kyverno PSS, generate + prove each gap, then full battery with fixes
    log("===== CLOSED LOOP: generate policies and re-run attacks =====")
    teardown_engines()
    install_kyverno()
    proofs = generate_and_prove(kyverno_gaps, by_engine["kyverno"])

    log("===== ENGINE 4: Kyverno + generated policies (full battery) =====")
    by_engine["kyverno+fixes"] = run_battery("kyverno+fixes")

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S EST")
    cov = write_reports(by_engine, proofs, generated_at)
    print()
    print((REPORT / "phase2-matrix.txt").read_text())
    proved = sum(1 for p in proofs if p.get("proved"))
    log(f"reports: {REPORT / 'scorecard.html'}  and  {REPORT / 'phase2-matrix.txt'}")
    if proved < 2:
        log(f"PHASE2_INCOMPLETE: only {proved} gap(s) proved closed (need >= 2)")
        return 1
    log(f"PHASE2_OK: {proved} gaps proved closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
