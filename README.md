<h1 align="center">K8s Admission Attack Lab</h1>

<p align="center">A disposable lab that checks whether Kubernetes admission controllers block the attack at deploy time</p>

<p align="center">
  <img alt="Kyverno" src="https://img.shields.io/badge/Kyverno-ValidatingPolicy-444">
  <img alt="OPA Gatekeeper" src="https://img.shields.io/badge/OPA-Gatekeeper-444">
  <img alt="Pod Security Admission" src="https://img.shields.io/badge/PSA-restricted%20enforce-444">
  <img alt="MITRE ATT&amp;CK for Containers" src="https://img.shields.io/badge/MITRE-ATT%26CK%20for%20Containers-444">
  <img alt="Kali Linux" src="https://img.shields.io/badge/Kali-nmap%20%C2%B7%20nuclei%20%C2%B7%20peirates%20%C2%B7%20trivy-444">
  <img alt="Lab only" src="https://img.shields.io/badge/Lab-only-2a2a2a">
</p>

## What it is

The K8s Admission Attack Lab is a Kali-driven admission-time test for Kubernetes. It fires the same 14-manifest battery at Kyverno, OPA Gatekeeper, and built-in Pod Security Admission, one engine at a time. Whatever the stock gate admits becomes a Kyverno ValidatingPolicy, and the same attack is re-run until the webhook blocks it.

This is a policy-gate test, not a runtime detect-and-remediate tool.

**Guardrails:** disposable `kind` lab only; admission-time testing only (no host compromise, no peirates hostPath-cron); one engine at a time (~4 GiB RAM); tokens and kubeconfigs stay on the lab host; generated policies are lab starting points, not production drop-ins.

## How the K8s Admission Attack Lab works

<p align="center">
  <img src="assets/architecture.png" alt="How the K8s Admission Attack Lab works" width="900">
</p>

1. **You** start the lab and read the scorecard.
2. **K8s Admission Attack Lab** (`./run_all.sh`) installs missing Kali tools, stands up the cluster if needed, and drives the loop.
3. **kind cluster** `admission-lab` is a disposable single-node Kubernetes lab (`kindest/node:v1.31.0` by default).
4. **Admission engines** — Kyverno restricted PSS (Enforce), Gatekeeper PSP library constraints, and built-in PSA `enforce=restricted` — each see the same battery, one at a time.
5. **Kali tools** probe the live cluster: nmap on 6443, 10250, 10255, 2379, and NodePorts; nuclei Kubernetes templates; peirates from a test pod; trivy on battery images.
6. **Generated policies** are Kyverno `ValidatingPolicy` (CEL) YAML for whatever the stock engines admitted. Mappable Kali findings can enter the same generator.
7. **Scorecard** is the side-by-side matrix, coverage percentages, closed-loop proofs, and HTML/JSON under `report/`.

## Setup instructions

You can run this lab from the CLI on a disposable host. Sharing it as a Grok Bot is optional, and the public template link is not published yet.

### 1. Get the bot (optional)

**TODO:** The public Bot template link will be added after CreateBotShareJson publishes it. Until then, clone this repo and run the CLI (step 3).

Grok Bot shares a Bot template link, not a JSON import. The recipe is [`template/gateforge-template.json`](template/gateforge-template.json). To build the bot by hand:

1. Name it **K8s Admission Attack Lab** and paste the profile description from the JSON.
2. Add the four memories: lab-only admission testing, closed-loop workflow, honest Kali-tool reporting, lean usage.
3. Add [`skills/gateforge-lab/SKILL.md`](skills/gateforge-lab/SKILL.md) and [`skills/gateforge-getting-started/SKILL.md`](skills/gateforge-getting-started/SKILL.md). The getting-started skill runs first.
4. Leave routines and plugins empty.

### 2. Lab prerequisites

You need a disposable lab host you own — Kali Rolling, or any machine with Docker — and about 4 GiB of RAM so one admission engine can run at a time. Nothing to connect for the CLI path.

| Tool | Used for |
|------|----------|
| Docker, kind, kubectl, helm | `kind` cluster `admission-lab`, engine installs, apply / delete |
| nmap, nuclei, peirates, trivy | Kali discovery stage (`./run_all.sh` will apt-install these if they are missing) |

Do not point this at a production, shared, or third-party cluster.

### 3. Run the lab

The GitHub repo is still [ritvikindupuri/Gateforge](https://github.com/ritvikindupuri/Gateforge).

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

In the matrix, attack rows that were `ADMITTED` under a stock engine should be `BLOCKED` under **Kyverno + generated**; the `compliant` control must stay admitted and Running; closed-loop lines should say `[PROVED CLOSED]`.

## Results

Lab scorecards and a write-up of a disposable run are in [TEST_RESULTS.md](TEST_RESULTS.md). Sanitized artifacts also live under [`report/samples/`](report/samples/).

## What already exists

This lab is not a generic cluster scanner, and it is not a runtime defender.

| Tool | What it does | Where this lab differs |
|------|----------------|-------------------------|
| kube-hunter, peirates | Find or abuse cluster issues, then stop at the finding. | Findings are re-fired at live admission webhooks, then closed with a generated policy and a re-proof. |
| Kubescape, Polaris | Scan posture and configuration. | This lab applies workloads and records whether the webhook admitted them. |
| Kyverno Chainsaw | Tests policies you already wrote. | This lab tests engines you have not fully covered, then writes the missing policy. |
| Policy Reporter | Visualizes policy results. | This lab produces the matrix and the proof, not only a view. |
| IronClaw `--emit-policy`, Valqore `generate_policy` | Emit YAML from static scans. | Closest cousins. They do not run the same live battery against Kyverno, Gatekeeper, and PSA, then re-apply the admitted attack to the live webhook. |
| K8sGPT policy drafts | Assistant-style dry-run YAML. | No multi-engine live re-proof in this workflow. |

KARMA, a related project by the same author, is a runtime Kubernetes attack / detect / remediate loop. The K8s Admission Attack Lab is the deploy-time gate.

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

This lab is for disposable clusters you own. Use it only where you have permission. It is not a product assessment of Kyverno, Gatekeeper, or Kubernetes, and a 100% lab score is not a claim that a production cluster is safe.

Do not run this against production, shared, or third-party clusters. Do not use it to attack systems you do not own. The attack manifests, peirates probes, and generated policies exist to test admission webhooks, not to compromise hosts. The author and contributors are not responsible for misuse.

The Kali Linux dragon logomark in the architecture figure is the official mark from the [Kali Linux press pack](https://gitlab.com/kalilinux/documentation/press-pack), used unmodified to identify Kali Linux and its tools. Kali Linux™ is a trademark of OffSec. See [`assets/icons/README.md`](assets/icons/README.md) and [OffSec's trademark policy](https://www.kali.org/docs/policy/trademark/). This project is not affiliated with or endorsed by OffSec or the Kali project.

MIT. See [LICENSE](LICENSE).
