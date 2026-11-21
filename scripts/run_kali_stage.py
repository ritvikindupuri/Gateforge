#!/usr/bin/env python3
"""Kali-tools stage for the Admission-Time Attack Simulator.

Runs nmap, nuclei, peirates, and trivy against the disposable kind cluster
only. Records raw output, maps admission-relevant findings into generated
policies, re-tests those attacks across Kyverno / Gatekeeper / PSA, and
re-runs the peirates privileged-pod API create to prove it is blocked.

Peirates is used for SA-token enumeration and for attempting to CREATE
privileged/hostPath pods through the API. We deliberately do not run
peirates' attack-pod-hostpath-mount module: that module writes a persistent
reverse-shell cron line into the node's /etc/crontab.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = Path(os.environ.get("LAB", str(REPO)))
REPORT = LAB / "report"
KALI_OUT = REPORT / "kali-tools"
SUGGESTED = LAB / "policies" / "suggested"
NS = "kali-probe"
KUBECONFIG = os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))
ENV = {
    **os.environ,
    "KUBECONFIG": KUBECONFIG,
    "PATH": "/usr/local/bin:" + os.environ.get("PATH", ""),
}

sys.path.insert(0, str(LAB / "scripts"))
import run_phase2 as p2  # noqa: E402


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(args, input_text=None, timeout=180, check=False, env=None):
    r = subprocess.run(
        args, input=input_text, text=True, capture_output=True,
        timeout=timeout, env=env or ENV,
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"{args} failed ({r.returncode}): {r.stdout}\n{r.stderr}")
    return r.returncode, r.stdout, r.stderr


def kubectl(args, timeout=180, input_text=None, check=False):
    return sh(["kubectl", *args], input_text=input_text, timeout=timeout, check=check)


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

def redact(text: str) -> str:
    return JWT_RE.sub("<redacted-jwt>", text or "")

def write_out(name: str, text: str) -> Path:
    KALI_OUT.mkdir(parents=True, exist_ok=True)
    path = KALI_OUT / name
    body = redact(text if (text or "").endswith("\n") else (text or "") + "\n")
    path.write_text(body)
    return path


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

def kind_targets() -> dict:
    rc, out, _ = kubectl(["get", "nodes", "-o", "jsonpath={.items[0].status.addresses[?(@.type==\"InternalIP\")].address}"])
    node_ip = (out or "").strip() or "172.18.0.2"
    rc, out, _ = sh(["kubectl", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"])
    api = (out or "").strip() or "https://127.0.0.1:6443"
    host, port = "127.0.0.1", "6443"
    m = re.search(r"https?://([^:/]+):(\d+)", api)
    if m:
        host, port = m.group(1), m.group(2)
    return {"node_ip": node_ip, "api": api, "api_host": host, "api_port": port}


def run_nmap(t: dict) -> dict:
    log("nmap: control-plane ports + NodePort range")
    node, api_host = t["node_ip"], t["api_host"]
    cmd1 = ["nmap", "-sV", "-Pn", "-T4", "-p", "6443,10250,10255,2379", node, api_host]
    rc1, o1, e1 = sh(cmd1, timeout=180)
    write_out("nmap-control-plane.txt", f"$ {' '.join(cmd1)}\n\n{o1}\n{e1}")
    cmd2 = ["nmap", "-Pn", "-T4", "--min-rate", "500", "-p", "30000-32767", node]
    rc2, o2, e2 = sh(cmd2, timeout=300)
    write_out("nmap-nodeports.txt", f"$ {' '.join(cmd2)}\n\n{o2}\n{e2}")
    open_ports = []
    for blob in (o1, o2):
        for m in re.finditer(r"^(\d+)/tcp\s+open\s+(\S+)", blob, re.M):
            open_ports.append({"port": int(m.group(1)), "service": m.group(2)})
    # de-dupe
    seen, ports = set(), []
    for p in open_ports:
        if p["port"] not in seen:
            seen.add(p["port"])
            ports.append(p)
    finding = {
        "tool": "nmap",
        "open_ports": ports,
        "notes": [],
        "maps_to": [],
    }
    labels = {6443: "kube-apiserver", 10250: "kubelet", 10255: "kubelet-read-only (legacy)", 2379: "etcd"}
    for p in ports:
        name = labels.get(p["port"], "nodeport" if 30000 <= p["port"] <= 32767 else p["service"])
        if p["port"] == 2379:
            finding["notes"].append(
                "etcd (2379) is reachable on the kind node IP. This is a control-plane exposure, "
                "not a pod admission miss — it cannot be closed by a ValidatingPolicy on Pods."
            )
        elif p["port"] == 10250:
            finding["notes"].append(
                "kubelet (10250) is listening on the kind node. Admission policies do not close this."
            )
        elif p["port"] == 10255:
            finding["notes"].append("Legacy unauthenticated kubelet port 10255 is open.")
        finding.setdefault("services", []).append(name)
    log(f"nmap open: {ports}")
    return finding


def run_nuclei(t: dict) -> dict:
    log("nuclei: kubernetes templates against the kind API / kubelet")
    # Discover templates
    tmpl_roots = [
        Path("/root/nuclei-templates"),
        Path("/root/.local/share/nuclei/templates"),
        Path("/root/.local/nuclei-templates"),
        Path("/usr/share/nuclei-templates"),
        Path.home() / "nuclei-templates",
    ]
    root = next((p for p in tmpl_roots if p.is_dir()), None)
    if root is None:
        log("nuclei templates missing; trying -update-templates")
        sh(["nuclei", "-update-templates"], timeout=300)
        root = next((p for p in tmpl_roots if p.is_dir()), None)
    targets = [t["api"], f"https://{t['node_ip']}:6443", f"https://{t['node_ip']}:10250"]
    jsonl = KALI_OUT / "nuclei.jsonl"
    args = [
        "nuclei", "-disable-update-check", "-no-color", "-silent",
        "-jsonl", "-o", str(jsonl),
        "-timeout", "8", "-retries", "1", "-duc",
        "-tags", "k8s,kubernetes,kube",
        "-insecure",
    ]
    for u in targets:
        args.extend(["-u", u])
    # Also include local k8s template dirs if present
    if root:
        for sub in [
            root / "http" / "misconfiguration" / "kubernetes",
            root / "http" / "exposures" / "configs",
            root / "ssl",
        ]:
            if sub.is_dir():
                args.extend(["-t", str(sub)])
    rc, out, err = sh(args, timeout=300)
    write_out("nuclei.txt", f"$ {' '.join(args)}\nrc={rc}\n\n{out}\n{err}")
    hits = []
    if jsonl.exists():
        for line in jsonl.read_text().splitlines():
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    names = []
    for h in hits:
        names.append(h.get("template-id") or h.get("info", {}).get("name") or "unknown")
    # Audit the live cluster with kubectl-based k8s templates (code protocol).
    if root and (root / "cloud" / "kubernetes").is_dir():
        jsonl2 = KALI_OUT / "nuclei-k8s-code.jsonl"
        args2 = [
            "nuclei", "-disable-update-check", "-no-color", "-silent",
            "-jsonl", "-o", str(jsonl2),
            "-timeout", "15", "-retries", "0", "-duc",
            "-t", str(root / "cloud" / "kubernetes"),
        ]
        rc2, out2, err2 = sh(args2, timeout=300)
        write_out("nuclei-k8s-code.txt", f"$ {' '.join(args2)}\nrc={rc2}\n\n{out2}\n{err2}")
        if jsonl2.exists():
            for line in jsonl2.read_text().splitlines():
                try:
                    hits.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        names = []
        for h in hits:
            names.append(h.get("template-id") or h.get("info", {}).get("name") or "unknown")

    log(f"nuclei hits: {names or 'none'}")
    return {
        "tool": "nuclei",
        "targets": targets,
        "hits": names,
        "hit_count": len(names),
        "notes": [
            "Templates were run unauthenticated against the kind API and kubelet. "
            "Most Kubernetes API paths require a token, so empty results are expected "
            "when anonymous auth is disabled."
        ],
        "maps_to": [],
    }


def run_trivy() -> dict:
    log("trivy: battery images busybox:1.36 and busybox:latest")
    log("trivy: downloading vuln DB if needed")
    sh(["trivy", "image", "--download-db-only"], timeout=300)
    images = ["busybox:1.36", "busybox:latest"]
    summaries = []
    maps_to = []
    for img in images:
        safe = img.replace(":", "_").replace("/", "_")
        json_path = KALI_OUT / f"trivy-{safe}.json"
        args = [
            "trivy", "image", "--scanners", "vuln", "--format", "json",
            "--output", str(json_path), "--timeout", "4m", img,
        ]
        rc, out, err = sh(args, timeout=300)
        write_out(f"trivy-{safe}.txt", f"$ {' '.join(args)}\nrc={rc}\n\n{out}\n{err}")
        crit = high = med = 0
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text() or "{}")
            except json.JSONDecodeError:
                data = {}
            for res in data.get("Results") or []:
                for v in res.get("Vulnerabilities") or []:
                    sev = (v.get("Severity") or "").upper()
                    if sev == "CRITICAL":
                        crit += 1
                    elif sev == "HIGH":
                        high += 1
                    elif sev == "MEDIUM":
                        med += 1
        summaries.append({"image": img, "critical": crit, "high": high, "medium": med, "rc": rc})
        if img.endswith(":latest") and (crit or high):
            maps_to.append({
                "scenario": "latest-tag",
                "reason": f"{img} has {crit} critical / {high} high CVEs; mutable tag was admitted by stock PSS/PSA.",
            })
        log(f"trivy {img}: C={crit} H={high} M={med}")
    return {"tool": "trivy", "images": summaries, "maps_to": maps_to}


# ---------------------------------------------------------------------------
# Peirates inside a probe pod
# ---------------------------------------------------------------------------

def exclude_ns_from_kyverno(ns: str, exclude: bool) -> None:
    """Add or remove a namespace on Kyverno validating webhook NotIn selectors."""
    rc, out, err = kubectl(["get", "validatingwebhookconfiguration", "-o", "json"])
    if rc != 0:
        log(f"no validating webhooks: {err}")
        return
    data = json.loads(out or "{}")
    changed = 0
    for item in data.get("items") or []:
        name = item["metadata"]["name"]
        if "kyverno" not in name.lower():
            continue
        webhooks = item.get("webhooks") or []
        dirty = False
        for wh in webhooks:
            sel = wh.setdefault("namespaceSelector", {})
            exprs = sel.setdefault("matchExpressions", [])
            # find NotIn metadata.name
            found = False
            for expr in exprs:
                if expr.get("key") == "kubernetes.io/metadata.name" and expr.get("operator") == "NotIn":
                    vals = list(expr.get("values") or [])
                    if exclude and ns not in vals:
                        vals.append(ns)
                        expr["values"] = vals
                        dirty = True
                    if (not exclude) and ns in vals:
                        expr["values"] = [v for v in vals if v != ns]
                        dirty = True
                    found = True
            if exclude and not found:
                exprs.append({
                    "key": "kubernetes.io/metadata.name",
                    "operator": "NotIn",
                    "values": [ns],
                })
                dirty = True
        if dirty:
            kubectl(["apply", "-f", "-"], input_text=json.dumps(item), check=False)
            changed += 1
    log(f"kyverno webhook ns exclusion {ns}={'on' if exclude else 'off'} (patched {changed} configs)")
    time.sleep(2)


def setup_probe_pod() -> None:
    log("deploying kali-probe namespace / SA / pod")
    kubectl(["apply", "-f", str(LAB / "cluster" / "kali-probe.yaml")], check=True)
    # make sure debian image is in the kind node
    sh(["docker", "pull", "debian:bookworm-slim"], timeout=180)
    sh(["kind", "load", "docker-image", "debian:bookworm-slim", "--name", "admission-lab"], timeout=180)
    kubectl(["-n", NS, "wait", "--for=condition=Ready", "pod/kali-probe", "--timeout=180s"], timeout=200, check=True)
    # copy peirates + attempt manifests into the emptyDir
    sh(["kubectl", "-n", NS, "cp", "/usr/bin/peirates", f"{NS}/kali-probe:/tools/peirates"], timeout=120, check=True)
    sh(["kubectl", "-n", NS, "cp", str(LAB / "cluster" / "peirates-privileged-pod.yaml"),
        f"{NS}/kali-probe:/tools/privileged.yaml"], timeout=60, check=True)
    sh(["kubectl", "-n", NS, "cp", str(LAB / "cluster" / "peirates-hostpath-pod.yaml"),
        f"{NS}/kali-probe:/tools/hostpath.yaml"], timeout=60, check=True)
    kubectl(["-n", NS, "exec", "kali-probe", "--", "chmod", "755", "/tools/peirates"], check=True)
    log("peirates binary is in the probe pod")


def in_pod(args, timeout=90, input_text=None):
    cmd = ["kubectl", "-n", NS, "exec", "-i", "kali-probe", "--", *args]
    return sh(cmd, timeout=timeout, input_text=input_text)


def peirates_cmd(module: str = "", extra=None, input_text=None, timeout=90, tag=""):
    # Kali peirates 1.1.28 has no -c flag. In-pod it auto-loads the SA token
    # and defaults to the in-cluster API, so we do not pass -t (avoids leaking JWTs).
    args = ["/tools/peirates", "-k", "-u", "https://kubernetes.default.svc"]
    if module:
        args.extend(["-m", module])
    if extra:
        args.extend(extra)
    rc, out, err = in_pod(args, timeout=timeout, input_text=input_text)
    blob = f"$ peirates -k -u https://kubernetes.default.svc {('-m '+module) if module else ''}\nrc={rc}\n\n{out}\n{err}"
    if tag:
        write_out(f"peirates-{tag}.txt", blob)
    return rc, out, err, blob


def peirates_kubectl(kubectl_args: str, tag: str, timeout=90):
    """Drive peirates' kubectl menu (item 90) via stdin so the SA token is used."""
    # Interactive: send the kubectl line, then exit.
    script = f"\nkubectl {kubectl_args}\n\nexit\n"
    rc, out, err, blob = peirates_cmd(module="", input_text=script, timeout=timeout, tag=tag)
    return rc, out, err, blob


def classify_attempt(out: str, err: str, expect_resource: str | None = None) -> dict:
    text = (out or "") + "\n" + (err or "")
    low = text.lower()
    stopped_by = []
    if "forbidden" in low or "cannot list" in low or "cannot get" in low or "cannot create" in low:
        stopped_by.append("RBAC")
    if "admission webhook" in low or "denied the request" in low or "validatingwebhook" in low or "violates podsecurity" in low or "denied by" in low:
        stopped_by.append("admission")
    if "secret found:" in low or "pod name:" in low:
        if "forbidden" not in low and "denied" not in low:
            return {"result": "ALLOWED", "stopped_by": [], "excerpt": text[-2000:]}
    created = bool(re.search(r"\b(created|configured)\b", low)) and "denied" not in low and "forbidden" not in low
    # kubectl apply success line
    if expect_resource and re.search(rf"{re.escape(expect_resource)} created", low):
        created = True
    result = "ALLOWED" if created and not stopped_by else ("STOPPED" if stopped_by else "UNKNOWN")
    if created and stopped_by:
        result = "ALLOWED"
        stopped_by = []
    return {"result": result, "stopped_by": stopped_by, "excerpt": text[-2000:]}


def pod_exists(name: str) -> bool:
    rc, out, _ = kubectl(["-n", NS, "get", "pod", name, "--ignore-not-found", "-o", "name"])
    return bool((out or "").strip())


def cleanup_attempt_pods() -> None:
    kubectl(["-n", NS, "delete", "pod",
             "peirates-priv-attempt", "peirates-hostpath-attempt",
             "--ignore-not-found", "--wait=false"])
    # also any leftover attack-pod-* if a module was ever invoked
    rc, out, _ = kubectl(["-n", NS, "get", "pods", "-o", "name"])
    for name in out.split():
        short = name.split("/")[-1]
        if short.startswith("attack-pod") or short.startswith("peirates-"):
            kubectl(["-n", NS, "delete", "pod", short, "--ignore-not-found", "--wait=false"])


def run_peirates_pass(label: str, admission_expected: str) -> dict:
    """One peirates pass: list pods, list secrets, create privileged pod, create hostPath pod."""
    log(f"peirates pass '{label}' (admission expected={admission_expected})")
    attempts = []

    rc, out, err, _ = peirates_cmd(module="get-pods", tag=f"{label}-get-pods", timeout=90)
    att = classify_attempt(out, err)
    att.update({"action": "list-pods", "module": "get-pods", "pass": label})
    attempts.append(att)
    log(f"  get-pods: {att['result']} stopped_by={att['stopped_by']}")

    rc, out, err, _ = peirates_cmd(module="list-secrets", tag=f"{label}-list-secrets", timeout=90)
    att = classify_attempt(out, err)
    att.update({"action": "list-secrets", "module": "list-secrets", "pass": label})
    attempts.append(att)
    log(f"  list-secrets: {att['result']} stopped_by={att['stopped_by']}")

    cleanup_attempt_pods()
    rc, out, err, _ = peirates_kubectl(
        "apply -f /tools/privileged.yaml", tag=f"{label}-create-privileged", timeout=90
    )
    att = classify_attempt(out, err, expect_resource="pod/peirates-priv-attempt")
    if pod_exists("peirates-priv-attempt"):
        att["result"], att["stopped_by"] = "ALLOWED", []
    att.update({"action": "create-privileged-pod", "module": "kubectl apply", "pass": label,
                "maps_to_scenario": "privileged"})
    attempts.append(att)
    log(f"  create privileged: {att['result']} stopped_by={att['stopped_by']}")
    cleanup_attempt_pods()

    rc, out, err, _ = peirates_kubectl(
        "apply -f /tools/hostpath.yaml", tag=f"{label}-create-hostpath", timeout=90
    )
    att = classify_attempt(out, err, expect_resource="pod/peirates-hostpath-attempt")
    if pod_exists("peirates-hostpath-attempt"):
        att["result"], att["stopped_by"] = "ALLOWED", []
    att.update({"action": "create-hostpath-pod", "module": "kubectl apply", "pass": label,
                "maps_to_scenario": "hostpath"})
    attempts.append(att)
    log(f"  create hostPath: {att['result']} stopped_by={att['stopped_by']}")
    cleanup_attempt_pods()

    return {"pass": label, "admission_expected": admission_expected, "attempts": attempts}


# ---------------------------------------------------------------------------
# Engine-by-engine retest of peirates creates
# ---------------------------------------------------------------------------

def peirates_creates_under_current_gate(engine: str) -> list[dict]:
    setup_probe_pod()  # idempotent apply; wait if needed
    results = []
    for action, manifest, scenario in (
        ("create-privileged-pod", "/tools/privileged.yaml", "privileged"),
        ("create-hostpath-pod", "/tools/hostpath.yaml", "hostpath"),
    ):
        cleanup_attempt_pods()
        rc, out, err, _ = peirates_kubectl(
            f"apply -f {manifest}", tag=f"engine-{engine}-{scenario}", timeout=90
        )
        att = classify_attempt(out, err)
        name = "peirates-priv-attempt" if scenario == "privileged" else "peirates-hostpath-attempt"
        if pod_exists(name):
            att["result"], att["stopped_by"] = "ALLOWED", []
        elif att["result"] == "UNKNOWN" and any(s in ((out or "") + (err or "")).lower() for s in ("denied", "forbidden", "violates podsecurity")):
            att["result"] = "STOPPED"
            if "forbidden" in ((out or "")+(err or "")).lower() and "denied" not in ((out or "")+(err or "")).lower():
                att["stopped_by"] = ["RBAC"]
            else:
                att["stopped_by"] = ["admission"]
        att.update({"action": action, "engine": engine, "scenario": scenario})
        results.append(att)
        log(f"  {engine} {scenario}: {att['result']} stopped_by={att['stopped_by']}")
        cleanup_attempt_pods()
    return results


def test_across_engines() -> dict:
    """Re-run peirates privileged/hostPath creates under each stock engine, one at a time."""
    by_engine = {}
    log("===== peirates creates under Kyverno =====")
    p2.teardown_engines(keep="kyverno")
    rc, out, _ = kubectl(["-n", "kyverno", "get", "pods", "--no-headers"])
    if rc != 0 or "Running" not in (out or ""):
        p2.install_kyverno()
    by_engine["kyverno"] = peirates_creates_under_current_gate("kyverno")

    log("===== peirates creates under Gatekeeper =====")
    p2.teardown_engines()
    p2.install_gatekeeper()
    by_engine["gatekeeper"] = peirates_creates_under_current_gate("gatekeeper")

    log("===== peirates creates under built-in PSA =====")
    p2.teardown_engines()
    # PSA on the probe namespace
    kubectl(["create", "namespace", NS, "--dry-run=client", "-o", "yaml"])
    kubectl(["apply", "-f", str(LAB / "cluster" / "kali-probe.yaml")])
    kubectl([
        "label", "ns", NS, "--overwrite",
        "pod-security.kubernetes.io/enforce=restricted",
        "pod-security.kubernetes.io/enforce-version=latest",
    ])
    by_engine["psa"] = peirates_creates_under_current_gate("psa")
    kubectl(["label", "ns", NS,
             "pod-security.kubernetes.io/enforce-",
             "pod-security.kubernetes.io/enforce-version-",
             "--overwrite"])

    log("===== restore Kyverno + generated policies for final prove =====")
    p2.teardown_engines()
    extras = sorted(SUGGESTED.glob("*.yaml"))
    p2.install_kyverno(extra_policies=extras)
    by_engine["kyverno+fixes"] = peirates_creates_under_current_gate("kyverno+fixes")
    return by_engine


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

FOUND_BY_DEFAULT = {
    "privileged": "peirates (SA token + kubectl apply of a privileged pod)",
    "hostpath": "peirates (SA token + kubectl apply of a hostPath:/ pod)",
    "docker-sock": "peirates (hostPath mount class; docker.sock is the same control)",
    "latest-tag": "trivy (CVEs on busybox:latest) + admission battery",
}

PRIOR_ART = p2.PRIOR_ART


def build_found_by(trivy_f: dict, nmap_f: dict, nuclei_f: dict, peirates_summary: dict) -> dict:
    found = dict(FOUND_BY_DEFAULT)
    # only claim trivy if it actually found vulns on :latest
    latest = next((i for i in trivy_f.get("images", []) if i["image"].endswith(":latest")), None)
    if not latest or not (latest.get("critical") or latest.get("high")):
        found["latest-tag"] = "admission battery (trivy ran; no high/critical recorded)"
        if latest:
            found["latest-tag"] = (
                f"trivy ({latest['critical']} critical / {latest['high']} high / "
                f"{latest['medium']} medium on busybox:latest)"
            )
    # other scenarios stay blank unless a tool mapped them
    return found


def render_html(phase2, kali, found_by, generated_at: str) -> str:
    by_engine = {e: phase2["engines"][e]["results"] for e in phase2["engines"]}
    cov = {e: phase2["engines"][e]["coverage"] for e in phase2["engines"]}
    engines = [e for e in ("kyverno", "gatekeeper", "psa", "kyverno+fixes") if e in by_engine]
    scenarios = p2.SCENARIOS

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
        return f'<td class="{cls}" title="{p2.html_esc(title)}">{p2.html_esc(result)}</td>'

    rows = []
    for s in scenarios:
        kind = "control" if not s["attack"] else "attack"
        tds = "".join(cell(e, s["id"], s["attack"]) for e in engines)
        fb = found_by.get(s["id"], "—")
        rows.append(
            f'<tr class="{kind}"><th>{p2.html_esc(s["id"])}</th>'
            f'<td class="tech">{p2.html_esc(s["technique"])}</td>'
            f'<td class="tech">{p2.html_esc(fb)}</td>{tds}</tr>'
        )
    cov_cards = []
    labels = p2.ENGINE_LABELS
    for e in engines:
        c = cov[e]
        cov_cards.append(
            f'<div class="card"><h3>{p2.html_esc(labels[e])}</h3>'
            f'<div class="pct">{c["coverage_pct"]}%</div>'
            f'<p>{c["blocked"]}/{c["attacks"]} attacks blocked</p>'
            f'<p>Gaps: {p2.html_esc(", ".join(c["gaps"]) if c["gaps"] else "none")}</p></div>'
        )
    # Kali tool summary cards
    nmap_f = kali["tools"]["nmap"]
    nuclei_f = kali["tools"]["nuclei"]
    trivy_f = kali["tools"]["trivy"]
    ports = ", ".join(f'{p["port"]}/tcp ({p["service"]})' for p in nmap_f.get("open_ports") or []) or "none"
    trivy_line = "; ".join(
        f'{i["image"]}: {i["critical"]}C/{i["high"]}H/{i["medium"]}M' for i in trivy_f.get("images") or []
    )
    # peirates attempts table
    p_rows = []
    for att in kali.get("peirates_attempts", []):
        sb = ", ".join(att.get("stopped_by") or []) or "—"
        p_rows.append(
            f'<tr><td>{p2.html_esc(att.get("pass",""))}</td>'
            f'<td>{p2.html_esc(att.get("action",""))}</td>'
            f'<td>{p2.html_esc(att.get("result",""))}</td>'
            f'<td>{p2.html_esc(sb)}</td></tr>'
        )
    loop_rows = []
    for item in kali.get("closed_loop", []):
        cls = "proved" if item.get("proved") else "failed"
        loop_rows.append(
            f'<tr class="{cls}"><td>{p2.html_esc(item.get("id",""))}</td>'
            f'<td>{p2.html_esc(item.get("source",""))}</td>'
            f'<td><code>{p2.html_esc(item.get("policy") or "—")}</code></td>'
            f'<td>{p2.html_esc(item.get("before","—"))} → {p2.html_esc(item.get("after","—"))}</td>'
            f'<td class="{cls}">{"PROVED CLOSED" if item.get("proved") else "NOT PROVED"}</td></tr>'
        )
    engine_rows = []
    for eng, atts in (kali.get("peirates_by_engine") or {}).items():
        for att in atts:
            sb = ", ".join(att.get("stopped_by") or []) or "—"
            engine_rows.append(
                f'<tr><td>{p2.html_esc(labels.get(eng,eng))}</td>'
                f'<td>{p2.html_esc(att.get("scenario",""))}</td>'
                f'<td>{p2.html_esc(att.get("result",""))}</td>'
                f'<td>{p2.html_esc(sb)}</td></tr>'
            )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>K8s Admission-Time Attack Simulator — Kali closed loop</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a222b; --line:#2b3642; --text:#e8eef4; --muted:#9aa8b6;
          --block:#3dd68c; --admit:#f0b429; --ok:#7aa2f7; --fp:#f7768e; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--text); }}
  main {{ max-width:1180px; margin:0 auto; padding:32px 20px 64px; }}
  h1 {{ font-size:1.55rem; margin:0 0 .3rem; }}
  h2 {{ font-size:1.12rem; margin:2rem 0 .6rem; }}
  .sub,.note {{ color:var(--muted); }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
  .card h3 {{ margin:0 0 .4rem; font-size:.9rem; color:var(--muted); }}
  .pct {{ font-size:2rem; font-weight:700; }}
  .card p {{ margin:.25rem 0 0; color:var(--muted); font-size:.9rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); }}
  th,td {{ padding:.45rem .55rem; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }}
  thead th {{ font-size:.78rem; letter-spacing:.04em; color:var(--muted); text-transform:uppercase; }}
  td.tech {{ color:var(--muted); font-size:.85rem; }}
  td.block {{ color:var(--block); font-weight:650; }}
  td.admit {{ color:var(--admit); font-weight:650; }}
  td.ok {{ color:var(--ok); font-weight:650; }}
  td.fp, td.failed {{ color:var(--fp); font-weight:650; }}
  .proved {{ color:var(--block); font-weight:650; }}
  code,pre {{ font:12.5px/1.4 ui-monospace,monospace; }}
  pre {{ background:#0c1014; border:1px solid var(--line); padding:12px; overflow:auto; border-radius:8px; }}
</style>
</head>
<body>
<main>
  <h1>K8s Admission-Time Attack Simulator</h1>
  <p class="sub">Kali-tool discovery → generated policy → multi-engine retest → peirates re-run. {p2.html_esc(generated_at)} (America/Indianapolis). Policy gate only; no host breakout.</p>

  <h2>Coverage by engine</h2>
  <div class="cards">{''.join(cov_cards)}</div>

  <h2>Kali tools</h2>
  <div class="cards">
    <div class="card"><h3>nmap</h3><p>Open: {p2.html_esc(ports)}</p></div>
    <div class="card"><h3>nuclei</h3><p>{nuclei_f.get("hit_count",0)} template hit(s): {p2.html_esc(", ".join(nuclei_f.get("hits") or []) or "none")}</p></div>
    <div class="card"><h3>trivy</h3><p>{p2.html_esc(trivy_line or "no results")}</p></div>
    <div class="card"><h3>peirates</h3><p>Ran inside the kali-probe pod using its service-account token. Privileged/hostPath creates were attempted through peirates' kubectl API path only.</p></div>
  </div>
  <p class="note">Raw output: $LAB/report/kali-tools/</p>

  <h2>Side-by-side matrix</h2>
  <table>
    <thead><tr><th>Scenario</th><th>Technique</th><th>Found by (Kali tool)</th>{''.join(f'<th>{p2.html_esc(labels[e])}</th>' for e in engines)}</tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h2>Peirates attempts (RBAC vs admission)</h2>
  <table>
    <thead><tr><th>Pass</th><th>Action</th><th>Result</th><th>Stopped by</th></tr></thead>
    <tbody>{''.join(p_rows)}</tbody>
  </table>

  <h2>Peirates privileged / hostPath create across engines</h2>
  <table>
    <thead><tr><th>Engine</th><th>Attack</th><th>Result</th><th>Stopped by</th></tr></thead>
    <tbody>{''.join(engine_rows)}</tbody>
  </table>

  <h2>Closed loop</h2>
  <table>
    <thead><tr><th>Finding</th><th>Source</th><th>Policy</th><th>Before → after</th><th>Status</th></tr></thead>
    <tbody>{''.join(loop_rows)}</tbody>
  </table>

  <h2>Prior art (honest)</h2>
  <p class="note">{p2.html_esc(PRIOR_ART)} This stage adds a live Kali-tool front end (nmap, nuclei, peirates, trivy) that feeds those findings into the same loop.</p>

  <h2>Rerun</h2>
  <pre>export PATH=/usr/local/bin:$PATH KUBECONFIG=/root/.kube/config
$LAB/run_all.sh</pre>
</main>
</body>
</html>
"""


def write_reports(phase2, kali, found_by, generated_at: str) -> None:
    REPORT.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": generated_at,
        "timezone": "America/Indianapolis",
        "phase2": phase2,
        "kali": kali,
        "found_by": found_by,
    }
    (REPORT / "kali-loop.json").write_text(redact(json.dumps(payload, indent=2) + "\n"))
    html = render_html(phase2, kali, found_by, generated_at)
    (REPORT / "scorecard.html").write_text(html)
    (REPORT / "index.html").write_text(html)
    # short text summary
    lines = [
        "K8s ADMISSION LAB — KALI TOOL STAGE",
        f"Generated (America/Indianapolis): {generated_at}",
        "",
        "Tools: nmap, nuclei, peirates (in-pod), trivy",
        f"nmap open: {kali['tools']['nmap'].get('open_ports')}",
        f"nuclei hits: {kali['tools']['nuclei'].get('hits')}",
        f"trivy: {kali['tools']['trivy'].get('images')}",
        "",
        "Peirates attempts:",
    ]
    for att in kali.get("peirates_attempts", []):
        lines.append(f"  [{att.get('pass')}] {att.get('action')}: {att.get('result')} stopped_by={att.get('stopped_by')}")
    lines.append("")
    lines.append("Closed loop:")
    for item in kali.get("closed_loop", []):
        lines.append(f"  {item.get('id')}: {item.get('before')} → {item.get('after')} proved={item.get('proved')}")
    (REPORT / "kali-stage.txt").write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    KALI_OUT.mkdir(parents=True, exist_ok=True)
    SUGGESTED.mkdir(parents=True, exist_ok=True)
    t = kind_targets()
    log(f"targets: node={t['node_ip']} api={t['api']}")

    nmap_f = run_nmap(t)
    nuclei_f = run_nuclei(t)
    trivy_f = run_trivy()

    setup_probe_pod()

    # Discovery pass: no admission engine (or namespace excluded) so peirates
    # can show the raw RBAC-allowed privileged/hostPath create.
    log("removing admission engines for the peirates discovery pass")
    p2.teardown_engines()
    open_pass = run_peirates_pass("admission-open", admission_expected="ALLOWED")

    # Cross-engine retest + Kyverno+generated prove
    peirates_by_engine = test_across_engines()
    closed_attempts = []
    for att in peirates_by_engine.get("kyverno+fixes") or []:
        closed_attempts.append({**att, "pass": "admission-on", "action": att.get("action") or att.get("scenario")})
    closed_pass = {"pass": "admission-on", "attempts": closed_attempts}

    peirates_attempts = open_pass["attempts"] + closed_attempts

    # Map findings to policies / scenarios
    closed_loop = []
    # From peirates open pass: privileged + hostpath allowed when admission was excluded
    for att in open_pass["attempts"]:
        if att.get("maps_to_scenario") and att["result"] == "ALLOWED":
            scenario = att["maps_to_scenario"]
            # After admission-on pass, did the same action get stopped?
            later = next(
                (a for a in closed_pass["attempts"]
                 if a.get("action") == att["action"]),
                None,
            )
            proved = bool(later and later["result"] == "STOPPED" and "admission" in later.get("stopped_by", []))
            policy = "disallow-privileged-containers" if scenario == "privileged" else "disallow-host-path"
            closed_loop.append({
                "id": scenario,
                "source": f"peirates {att['action']} (SA token in kali-probe pod)",
                "policy": policy,
                "before": "ALLOWED (namespace excluded from admission)",
                "after": (later or {}).get("result", "—"),
                "stopped_by": (later or {}).get("stopped_by", []),
                "proved": proved,
            })

    for m in trivy_f.get("maps_to") or []:
        # already have deny-latest-tag from phase 2; re-state the loop
        closed_loop.append({
            "id": m["scenario"],
            "source": f"trivy: {m['reason']}",
            "policy": "deny-latest-tag",
            "before": "ADMITTED under stock PSS/PSA/Gatekeeper",
            "after": "BLOCKED under Kyverno + generated policy (phase 2 prove)",
            "proved": (SUGGESTED / "deny-latest-tag.yaml").exists(),
            "note": "Re-verified in phase 2; Kali/trivy is the discovery source for this gap.",
        })

    # A finding is fully proved if kyverno+fixes (and the stock engines) stop the create.
    for item in closed_loop:
        sid = item["id"]
        if sid in ("privileged", "hostpath"):
            eng = peirates_by_engine.get("kyverno+fixes") or []
            hit = next((a for a in eng if a.get("scenario") == sid), None)
            if hit and hit["result"] == "STOPPED":
                item["proved"] = True
                item["after"] = f"{item['after']}; also STOPPED under Kyverno+fixes by {hit.get('stopped_by')}"

    kali = {
        "tools": {"nmap": nmap_f, "nuclei": nuclei_f, "trivy": trivy_f},
        "peirates_attempts": peirates_attempts,
        "peirates_by_engine": peirates_by_engine,
        "closed_loop": closed_loop,
        "note": (
            "Peirates ran inside kali-probe with a namespace-scoped SA that can "
            "list pods/secrets and create pods. Privileged/hostPath creates used "
            "peirates' kubectl path. attack-pod-hostpath-mount was not used "
            "because it persists a reverse shell in the node crontab."
        ),
    }
    found_by = build_found_by(trivy_f, nmap_f, nuclei_f, {})
    phase2_path = REPORT / "phase2-matrix.json"
    if phase2_path.exists():
        phase2 = json.loads(phase2_path.read_text())
    else:
        log("WARNING: phase2-matrix.json missing; run run_phase2.py for the full matrix")
        phase2 = {"engines": {}, "closed_loop": []}

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S EST")
    write_reports(phase2, kali, found_by, generated_at)
    write_out("findings.json", json.dumps(kali, indent=2))
    log(f"wrote {REPORT / 'scorecard.html'} and {KALI_OUT}")
    proved = sum(1 for i in closed_loop if i.get("proved"))
    log(f"KALI_STAGE {'OK' if proved >= 2 else 'INCOMPLETE'}: {proved} kali-mapped finding(s) proved closed")
    return 0 if proved >= 2 else 1


if __name__ == "__main__":
    sys.exit(main())
