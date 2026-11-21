<p align="center">
  <img src="assets/icon.svg" alt="" width="96">
</p>

<h1 align="center">Gateforge</h1>

<p align="center">Prove your Kubernetes admission gate actually blocks the attack</p>

<p align="center">
  <img alt="Kyverno" src="https://img.shields.io/badge/Kyverno-ValidatingPolicy-444">
  <img alt="OPA Gatekeeper" src="https://img.shields.io/badge/OPA-Gatekeeper-444">
  <img alt="Pod Security Admission" src="https://img.shields.io/badge/PSA-restricted%20enforce-444">
  <img alt="MITRE ATT&amp;CK for Containers" src="https://img.shields.io/badge/MITRE-ATT%26CK%20for%20Containers-444">
  <img alt="Kali Linux" src="https://img.shields.io/badge/Kali-nmap%20%C2%B7%20nuclei%20%C2%B7%20peirates%20%C2%B7%20trivy-444">
  <img alt="Lab only" src="https://img.shields.io/badge/Lab-only-2a2a2a">
</p>

## What it is

Gateforge is a Kali-driven admission-time attack loop for Kubernetes. It fires the same 14-manifest battery at Kyverno, OPA Gatekeeper, and built-in Pod Security Admission, one engine at a time. Whatever the stock gate admits becomes a Kyverno ValidatingPolicy, and the same attack is re-run until the webhook blocks it.

This is a policy-gate test, not a runtime detect-and-remediate tool.

**Guardrails:** disposable `kind` lab only; admission-time testing only (no host compromise, no peirates hostPath-cron); one engine at a time (~4 GiB RAM); tokens and kubeconfigs stay on the lab host; generated policies are lab starting points, not production drop-ins.

## How Gateforge works

<p align="center">
  <img src="assets/architecture.png" alt="How Gateforge works" width="900">
</p>

1. **You** start the lab and read the scorecard.
2. **Gateforge** (`./run_all.sh`) installs missing Kali tools, stands up the cluster if needed, and drives the loop.
3. **kind cluster** `admission-lab` is a disposable single-node Kubernetes lab (`kindest/node:v1.31.0` by default).
4. **Admission engines** — Kyverno restricted PSS (Enforce), Gatekeeper PSP library constraints, and built-in PSA `enforce=restricted` — each see the same battery, one at a time.
5. **Kali tools** probe the live cluster: nmap on 6443, 10250, 10255, 2379, and NodePorts; nuclei Kubernetes templates; peirates from a test pod; trivy on battery images.
6. **Generated policies** are Kyverno `ValidatingPolicy` (CEL) YAML for whatever the stock engines admitted. Mappable Kali findings can enter the same generator.
7. **Scorecard** is the side-by-side matrix, coverage percentages, closed-loop proofs, and HTML/JSON under `report/`.

## Quickstart

You need Docker, kind, kubectl, helm, and about 4 GiB of RAM. Kali Rolling is the path this repo was built on; `./run_all.sh` will apt-install nmap, nuclei, peirates, and trivy if they are missing.

```bash
git clone https://github.com/ritvikindupuri/Gateforge.git
cd Gateforge
sudo ./run_all.sh
```

Reports land in `report/scorecard.html`, `report/phase2-matrix.txt`, and `report/kali-tools/`. `LAB` defaults to the repo root; `KUBECONFIG` defaults to `~/.kube/config`.

To run a stage on its own:

```bash
./scripts/setup.sh                 # kind + Kyverno PSS
python3 scripts/run_phase2.py      # multi-engine battery + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, loop
```

Check three things in the matrix: attack rows that were `ADMITTED` under a stock engine should be `BLOCKED` under **Kyverno + generated**; the `compliant` control must stay admitted and Running; closed-loop lines should say `[PROVED CLOSED]`.

A few honest limits from the lab implementation: nmap hits on etcd or kubelet are recorded, not turned into Pod policies; nuclei `-code` findings on stock kube-system objects are recorded, not auto-enforced; peirates `get-pods` / `list-secrets` test RBAC, while privileged and hostPath *creates* are issued with in-pod `kubectl` as `kali-probe-sa` (the packaged peirates kubectl menu is not used); a trivy zero-CVE result is not a claim that the image is clean.

## Sample results

From a disposable lab run on 2026-11-20 (America/Indianapolis). Your numbers will move with engine versions and policy packs.

```
SCENARIO            Kyverno PSS    Gatekeeper PSP   Built-in PSA  Kyverno + generated
-------------------------------------------------------------------------------------
privileged            BLOCKED         BLOCKED         BLOCKED         BLOCKED
hostpath              BLOCKED         BLOCKED         BLOCKED         BLOCKED
hostnetwork           BLOCKED         BLOCKED         BLOCKED         BLOCKED
run-as-root           BLOCKED         BLOCKED         BLOCKED         BLOCKED
docker-sock           BLOCKED         BLOCKED         BLOCKED         BLOCKED
latest-tag            ADMITTED        ADMITTED        ADMITTED        BLOCKED
no-limits             ADMITTED        ADMITTED        ADMITTED        BLOCKED
compliant             ADMITTED        ADMITTED        ADMITTED        ADMITTED      (control)
hostpid               BLOCKED         BLOCKED         BLOCKED         BLOCKED
hostipc               BLOCKED         BLOCKED         BLOCKED         BLOCKED
cap-sys-admin         BLOCKED         BLOCKED         BLOCKED         BLOCKED
cap-net-raw           BLOCKED         BLOCKED         BLOCKED         BLOCKED
untrusted-registry    ADMITTED        ADMITTED        ADMITTED        BLOCKED
writable-rootfs       ADMITTED        BLOCKED         ADMITTED        BLOCKED

Coverage = attacks blocked / attack scenarios (control excluded).
  Kyverno PSS:         69.2%  (9/13)   gaps: latest-tag, no-limits, untrusted-registry, writable-rootfs
  Gatekeeper PSP:      76.9%  (10/13)  gaps: latest-tag, no-limits, untrusted-registry
  Built-in PSA:        69.2%  (9/13)   gaps: latest-tag, no-limits, untrusted-registry, writable-rootfs
  Kyverno + generated: 100.0% (13/13)  gaps: none   compliant still ADMITTED; Running

Closed loop (finding → generated Kyverno policy → re-run):
  latest-tag          ADMITTED → deny-latest-tag            → BLOCKED  [PROVED CLOSED]
  no-limits           ADMITTED → require-resource-limits    → BLOCKED  [PROVED CLOSED]
  untrusted-registry  ADMITTED → restrict-image-registries  → BLOCKED  [PROVED CLOSED]
  writable-rootfs     ADMITTED → require-readonly-rootfs    → BLOCKED  [PROVED CLOSED]
```

Kali-tool stage from the same lab (20:00 EST, America/Indianapolis): nmap found 6443, 10250, and 2379 open; 10255 closed; no NodePorts; anonymous API 403. nuclei had 33 matches / 20 unique `-code` templates (mostly kube-system) and no anonymous HTTP hits. trivy reported 0 critical / high / medium on `busybox:1.36` and `busybox:latest`. peirates could list pods and a canary secret (RBAC); privileged and hostPath creates were allowed with no admission engine and stopped under Kyverno, Gatekeeper, PSA, and Kyverno + generated.

Sanitized artifacts: [`report/samples/`](report/samples/).

## What already exists

Gateforge is not a generic cluster scanner, and it is not a runtime defender.

| Tool | What it does | Where Gateforge differs |
|------|----------------|-------------------------|
| kube-hunter, peirates | Find or abuse cluster issues, then stop at the finding. | Findings are re-fired at live admission webhooks, then closed with a generated policy and a re-proof. |
| Kubescape, Polaris | Scan posture and configuration. | Gateforge applies workloads and records whether the webhook admitted them. |
| Kyverno Chainsaw | Tests policies you already wrote. | Gateforge tests engines you have not fully covered, then writes the missing policy. |
| Policy Reporter | Visualizes policy results. | Gateforge produces the matrix and the proof, not only a view. |
| IronClaw `--emit-policy`, Valqore `generate_policy` | Emit YAML from static scans. | Closest cousins. They do not run the same live battery against Kyverno, Gatekeeper, and PSA, then re-apply the admitted attack to the live webhook. |
| K8sGPT policy drafts | Assistant-style dry-run YAML. | No multi-engine live re-proof in this workflow. |

KARMA, a related project by the same author, is a runtime Kubernetes attack / detect / remediate loop. Gateforge is the deploy-time gate.

## MITRE ATT&CK for Containers

| Scenario or attempt | Technique | ID |
|---------------------|-----------|----|
| privileged, cap-sys-admin, hostpath, hostpid | Escape to Host | [T1611](https://attack.mitre.org/techniques/T1611/) |
| docker-sock | Container Administration Command | [T1609](https://attack.mitre.org/techniques/T1609/) |
| run-as-root, cap-sys-admin | Abuse Elevation Control Mechanism | [T1548](https://attack.mitre.org/techniques/T1548/) |
| hostnetwork, cap-net-raw | Network Boundary Bridging / Network Sniffing | [T1599](https://attack.mitre.org/techniques/T1599/), [T1040](https://attack.mitre.org/techniques/T1040/) |
| hostipc | Unsecured Credentials (shared IPC) | [T1552](https://attack.mitre.org/techniques/T1552/) |
| latest-tag, untrusted-registry | Supply Chain Compromise / Implant Internal Image | [T1195](https://attack.mitre.org/techniques/T1195/), [T1525](https://attack.mitre.org/techniques/T1525/) |
| no-limits | Resource Hijacking | [T1496](https://attack.mitre.org/techniques/T1496/) |
| writable-rootfs | File and Directory Permissions Modification | [T1222](https://attack.mitre.org/techniques/T1222/) |
| peirates list-pods | Container and Resource Discovery | [T1613](https://attack.mitre.org/techniques/T1613/) |
| peirates list-secrets | Unsecured Credentials / Valid Accounts | [T1552](https://attack.mitre.org/techniques/T1552/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| peirates create privileged / hostPath pod | Deploy Container + Escape to Host | [T1610](https://attack.mitre.org/techniques/T1610/), [T1611](https://attack.mitre.org/techniques/T1611/) |

Applying a workload through admission is itself [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/). The table lists the technique each scenario is meant to exercise if the gate admits it.

## Disclaimer

Gateforge is an authorized lab tool for disposable clusters you own. Use it only where you have permission. It is not a product assessment of Kyverno, Gatekeeper, or Kubernetes, and a 100% lab score is not a claim that a production cluster is safe.

Do not run this against production, shared, or third-party clusters. Do not use it to attack systems you do not own. The attack manifests, peirates probes, and generated policies exist to test admission webhooks, not to compromise hosts. The author and contributors are not responsible for misuse.

The Kali Linux dragon logomark in the architecture figure is the official mark from the [Kali Linux press pack](https://gitlab.com/kalilinux/documentation/press-pack), used unmodified to identify Kali Linux and its tools. Kali Linux™ is a trademark of OffSec. See [`assets/icons/README.md`](assets/icons/README.md) and [OffSec's trademark policy](https://www.kali.org/docs/policy/trademark/). This project is not affiliated with or endorsed by OffSec or the Kali project.

MIT. See [LICENSE](LICENSE).
