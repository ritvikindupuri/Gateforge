#!/usr/bin/env python3
"""K8s Admission-Time Attack Simulator — Phase 1 scorecard.

Applies crafted manifests and records whether Kyverno's admission webhook
BLOCKED or ADMITTED each one. This measures the policy GATE at deploy time,
not runtime behavior (that is what KARMA already covers).
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
NS = "admission-lab"
KUBECONFIG = os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))
ENV = {**os.environ, "KUBECONFIG": KUBECONFIG, "PATH": "/usr/local/bin:" + os.environ.get("PATH", "")}

# Expected outcomes under Kyverno restricted PSS (enforce).
# latest-tag and no-limits are intentional PSS coverage-gap demonstrations.
SCENARIOS = [
    {
        "id": "privileged",
        "file": "01-privileged.yaml",
        "title": "Privileged container",
        "technique": "securityContext.privileged=true",
        "expect": "BLOCKED",
        "pss_level": "baseline",
        "wait_running": False,
    },
    {
        "id": "hostpath",
        "file": "02-hostpath.yaml",
        "title": "hostPath mount of /etc",
        "technique": "volumes.hostPath.path=/etc",
        "expect": "BLOCKED",
        "pss_level": "baseline",
        "wait_running": False,
    },
    {
        "id": "hostnetwork",
        "file": "03-hostnetwork.yaml",
        "title": "hostNetwork pod",
        "technique": "spec.hostNetwork=true",
        "expect": "BLOCKED",
        "pss_level": "baseline",
        "wait_running": False,
    },
    {
        "id": "run-as-root",
        "file": "04-run-as-root.yaml",
        "title": "Explicit runAsUser 0",
        "technique": "securityContext.runAsUser=0",
        "expect": "BLOCKED",
        "pss_level": "restricted",
        "wait_running": False,
    },
    {
        "id": "docker-sock",
        "file": "05-docker-sock.yaml",
        "title": "Docker socket hostPath mount",
        "technique": "hostPath /var/run/docker.sock",
        "expect": "BLOCKED",
        "pss_level": "baseline",
        "wait_running": False,
    },
    {
        "id": "latest-tag",
        "file": "06-latest-tag.yaml",
        "title": "Mutable :latest image tag",
        "technique": "image: busybox:latest (otherwise PSS-compliant)",
        "expect": "ADMITTED",
        "pss_level": "gap",
        "wait_running": False,
        "note": "Stock Pod Security Standards do not restrict image tags.",
    },
    {
        "id": "no-limits",
        "file": "07-no-limits.yaml",
        "title": "No CPU/memory limits",
        "technique": "container has no resources.limits (otherwise PSS-compliant)",
        "expect": "ADMITTED",
        "pss_level": "gap",
        "wait_running": False,
        "note": "Stock Pod Security Standards do not require resource limits.",
    },
    {
        "id": "compliant",
        "file": "08-compliant.yaml",
        "title": "Restricted-compliant workload",
        "technique": "non-root, drop ALL, pinned tag, limits, no host access",
        "expect": "ADMITTED",
        "pss_level": "none",
        "wait_running": True,
        "note": "Control case: should be admitted and reach Running.",
    },
]

POLICY_RE = re.compile(
    r"(?m)^([a-z0-9][a-z0-9-]+):\s*$|"
    r"clusterpolicy/([a-z0-9-]+)|"
    r"policy '([a-z0-9-]+)'|"
    r"failed to (?:apply|process) policy ([a-z0-9-]+)",
    re.IGNORECASE,
)


def sh(args, input_text=None, timeout=90):
    r = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=ENV,
    )
    return r.returncode, r.stdout, r.stderr


def kubectl(args, timeout=90, input_text=None):
    return sh(["kubectl", *args], input_text=input_text, timeout=timeout)


def parse_policies(text: str) -> list[str]:
    """Extract Kyverno policy names from an admission-denied error."""
    names = []
    # Common Kyverno deny body: a policy name on its own line followed by a rule indent
    for m in re.finditer(r"(?m)^([a-z][a-z0-9-]{3,}):\s*$", text):
        names.append(m.group(1))
    # "blocked due to the following policies" then names
    if "following policies" in text.lower() or "policy" in text.lower():
        for m in re.finditer(r"Policy\s+([a-z0-9-]+)\s+failed:", text):
            names.append(m.group(1))
        for m in re.finditer(
            r"(disallow-[a-z0-9-]+|require-[a-z0-9-]+|restrict-[a-z0-9-]+|drop-[a-z0-9-]+)",
            text,
        ):
            names.append(m.group(1))
    # de-dupe, preserve order
    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def pod_name_from_manifest(path: Path) -> str | None:
    rc, out, err = sh(["kubectl", "apply", "--dry-run=client", "-f", str(path), "-o", "jsonpath={.metadata.name}"])
    if rc == 0 and out.strip():
        return out.strip()
    return None


def wait_running(name: str, timeout=90) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        rc, out, err = kubectl(
            ["-n", NS, "get", "pod", name, "-o", "jsonpath={.status.phase}"]
        )
        last = (out or err or "").strip()
        if last == "Running":
            return True, last
        if last in {"Failed", "Succeeded"}:
            return False, last
        time.sleep(2)
    rc, desc, _ = kubectl(["-n", NS, "describe", "pod", name], timeout=30)
    return False, f"timeout phase={last}\n{desc[-800:]}"


def apply_one(s: dict) -> dict:
    path = MANIFESTS / s["file"]
    name = pod_name_from_manifest(path) or f"att-{s['id']}"
    kubectl(["-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=true"], timeout=60)

    t0 = time.time()
    rc, out, err = kubectl(["apply", "-f", str(path)], timeout=60)
    text = (out or "") + (err or "")
    elapsed_ms = int((time.time() - t0) * 1000)
    admitted = rc == 0
    result = "ADMITTED" if admitted else "BLOCKED"
    policies = parse_policies(text) if not admitted else []
    running = None
    run_detail = ""
    if admitted and s.get("wait_running"):
        ok, run_detail = wait_running(name, timeout=90)
        running = ok
    elif admitted:
        # Confirm the object exists, then clean it up so later cases stay isolated.
        running = None
        kubectl(["-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=false"], timeout=30)
    else:
        # If a previous leftover exists we already tried to delete; nothing to do.
        pass

    if admitted and s.get("wait_running"):
        # Leave the compliant pod running briefly so the user can see it, then delete.
        kubectl(["-n", NS, "delete", "pod", name, "--ignore-not-found", "--wait=false"], timeout=30)

    match = result == s["expect"]
    if result == "BLOCKED" and s["expect"] == "BLOCKED":
        verdict = "ENFORCED"
    elif result == "ADMITTED" and s["expect"] == "ADMITTED" and s["pss_level"] == "gap":
        verdict = "COVERAGE GAP (admitted; no PSS rule)"
    elif result == "ADMITTED" and s["expect"] == "ADMITTED":
        verdict = "CLEAN (admitted as expected)"
        if s.get("wait_running"):
            verdict = "CLEAN (admitted and Running)" if running else "ADMITTED BUT NOT RUNNING"
    elif result == "ADMITTED" and s["expect"] == "BLOCKED":
        verdict = "POLICY MISS (expected block, admitted)"
    else:
        verdict = "UNEXPECTED BLOCK (expected admit)"

    return {
        "id": s["id"],
        "title": s["title"],
        "technique": s["technique"],
        "pss_level": s["pss_level"],
        "expected": s["expect"],
        "result": result,
        "match": match,
        "policies": policies,
        "pod_ran": running,
        "verdict": verdict,
        "latency_ms": elapsed_ms,
        "message": text.strip()[:1500],
        "run_detail": (run_detail or "")[:800],
        "note": s.get("note", ""),
    }


def render_table(results: list[dict]) -> str:
    cols = [
        ("ID", 14),
        ("RESULT", 9),
        ("EXPECTED", 9),
        ("PSS", 10),
        ("POLICY GATE", 36),
        ("VERDICT", 34),
    ]
    header = "  ".join(name.ljust(width) for name, width in cols)
    sep = "-" * len(header)
    lines = [
        "K8s ADMISSION-TIME ATTACK SIMULATOR  —  POLICY ENFORCEMENT SCORECARD",
        f"Generated (America/Indianapolis): {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}".rstrip(),
        "Cluster: kind-admission-lab    Gate: Kyverno restricted Pod Security Standards (Enforce)",
        "",
        header,
        sep,
    ]
    for r in results:
        gate = ", ".join(r["policies"]) if r["policies"] else ("—" if r["result"] == "ADMITTED" else "(see message)")
        row = [
            (r["id"], 14),
            (r["result"], 9),
            (r["expected"], 9),
            (r["pss_level"], 10),
            (gate, 36),
            (r["verdict"], 34),
        ]
        lines.append("  ".join(val[:width].ljust(width) for val, width in row))
    lines.append(sep)
    blocked = sum(1 for r in results if r["result"] == "BLOCKED")
    admitted = sum(1 for r in results if r["result"] == "ADMITTED")
    gaps = [r["id"] for r in results if "GAP" in r["verdict"]]
    misses = [r["id"] for r in results if "MISS" in r["verdict"] or "UNEXPECTED" in r["verdict"] or "NOT RUNNING" in r["verdict"]]
    lines.append(f"Blocked {blocked}/{len(results)}    Admitted {admitted}/{len(results)}")
    lines.append(f"PSS coverage gaps (admitted, no rule): {', '.join(gaps) if gaps else 'none'}")
    lines.append(f"Unexpected outcomes: {', '.join(misses) if misses else 'none'}")
    lines.append("")
    lines.append("Notes:")
    for r in results:
        if r.get("note"):
            lines.append(f"  - {r['id']}: {r['note']}")
    return "\n".join(lines) + "\n"


def cluster_info() -> dict:
    info = {}
    rc, out, _ = kubectl(["config", "current-context"])
    info["context"] = out.strip()
    rc, out, _ = kubectl(["get", "nodes", "-o", "wide"])
    info["nodes"] = out.strip()
    rc, out, _ = kubectl(["-n", "kyverno", "get", "pods", "-o", "wide"])
    info["kyverno_pods"] = out.strip()
    rc, out, _ = kubectl(["get", "validatingpolicy", "-o", "custom-columns=NAME:.metadata.name,READY:.status.conditions[?(@.type==\"Ready\")].status,ACTIONS:.spec.validationActions"])
    if rc != 0:
        rc, out, _ = kubectl(["get", "validatingpolicy"])
    info["validatingpolicies"] = out.strip()
    rc, out, _ = kubectl(["get", "clusterpolicy", "--ignore-not-found=true"])
    info["clusterpolicies"] = out.strip()
    rc, out, err = sh(["helm", "list", "-n", "kyverno"])
    info["helm"] = (out or err).strip()
    return info


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    manifest = f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {NS}\n"
    kubectl(["apply", "-f", "-"], input_text=manifest)

    results = []
    for s in SCENARIOS:
        print(f"--> {s['id']} ({s['file']}) ...", flush=True)
        try:
            r = apply_one(s)
        except subprocess.TimeoutExpired:
            r = {
                "id": s["id"],
                "title": s["title"],
                "technique": s["technique"],
                "pss_level": s["pss_level"],
                "expected": s["expect"],
                "result": "ERROR",
                "match": False,
                "policies": [],
                "pod_ran": None,
                "verdict": "TIMEOUT",
                "latency_ms": None,
                "message": "kubectl timed out",
                "run_detail": "",
                "note": s.get("note", ""),
            }
        results.append(r)
        print(f"    {r['result']:9}  {r['verdict']}  policies={r['policies']}", flush=True)

    info = cluster_info()
    generated = datetime.datetime.now().isoformat(timespec="seconds")
    report = {
        "generated": generated,
        "timezone": "America/Indianapolis",
        "cluster": "kind-admission-lab",
        "gate": "Kyverno restricted Pod Security Standards (validationFailureAction=Enforce)",
        "focus": "admission-time policy enforcement (not runtime detection)",
        "cluster_info": info,
        "scenarios": results,
        "summary": {
            "total": len(results),
            "blocked": sum(1 for r in results if r["result"] == "BLOCKED"),
            "admitted": sum(1 for r in results if r["result"] == "ADMITTED"),
            "expected_matches": sum(1 for r in results if r["match"]),
            "coverage_gaps": [r["id"] for r in results if "GAP" in r["verdict"]],
        },
    }
    json_path = REPORT / "scorecard.json"
    txt_path = REPORT / "scorecard.txt"
    table = render_table(results)
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    txt_path.write_text(table)
    print()
    print(table)
    print(f"Wrote {json_path}")
    print(f"Wrote {txt_path}")
    # Phase 1 success: at least one blocked and one clean run (admitted, and Running if we waited)
    blocked_ok = any(r["result"] == "BLOCKED" for r in results)
    clean = next((r for r in results if r["id"] == "compliant"), None)
    clean_ok = bool(clean and clean["result"] == "ADMITTED" and clean.get("pod_ran") is True)
    if blocked_ok and clean_ok:
        print("PHASE1_OK: at least one blocked and compliant pod ran clean")
        return 0
    print("PHASE1_INCOMPLETE: need at least one BLOCKED and a Running compliant pod")
    return 1


if __name__ == "__main__":
    sys.exit(main())
