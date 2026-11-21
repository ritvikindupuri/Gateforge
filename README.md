<p align="center">
  <img src="assets/icons/kubernetes.png" alt="K8s Admission Attack Lab" width="80">
</p>

<h1 align="center">K8s Admission Attack Lab</h1>

<p align="center"><strong>K8Admission</strong></p>

<p align="center">A lab that attacks Kubernetes admission controllers at deploy time and proves which attacks get through</p>

Admission controllers are the last gate before a pod runs. This lab attacks that gate, records which attacks slip through, and proves how to close them.

It runs on a [kind](https://kind.sigs.k8s.io/) cluster (a local Kubernetes cluster) on Kali, or on any host with Docker. Thirteen attack pods and one compliant control pod are applied to Kyverno, OPA Gatekeeper, and built-in Pod Security Admission (PSA), one engine at a time. Admitted attacks are turned into Kyverno ValidatingPolicies — rules that reject matching pods — then the attack pod is applied again to prove the gap is closed.

On a clean lab run:

| Engine | Coverage |
|--------|----------|
| Kyverno | 69.2% (9/13) |
| OPA Gatekeeper | 76.9% (10/13) |
| Built-in PSA | 69.2% (9/13) |
| Kyverno + generated policies | 100% (13/13) |

Coverage = attack pods blocked ÷ 13 attack pods. The compliant control pod is not counted and must stay admitted. Generated policies closed four gaps: latest tag, no resource limits, untrusted registry, and a writable root filesystem. The full write-up is in [TEST_RESULTS.md](TEST_RESULTS.md).

## Key Features

- **Two ways to run it.** `sudo ./run_all.sh` on Kali, or the [Grok Bot](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) runs that script for you.
- **One engine at a time.** Kyverno is scored with restricted Pod Security Standards (PSS) in Enforce mode, then removed; then OPA Gatekeeper with the PodSecurityPolicy (PSP) library; then built-in PSA with `enforce=restricted`.
- **Policies you can read.** Each admitted attack produces a Kyverno ValidatingPolicy under `policies/suggested/` before it is applied and re-tested.
- **Kali-tool stage.** nmap, nuclei, peirates, and trivy probe the live cluster and write output to `report/kali-tools/`.
- **Reports in HTML and text.** Coverage, the per-engine matrix, and `[PROVED CLOSED]` lines are in `report/scorecard.html` and `report/phase2-matrix.txt`.

## How It Works

<p align="center">
  <img src="assets/architecture.png" alt="How the K8s Admission Attack Lab works" width="800">
</p>

1. **You** start from Path A (the CLI) or Path B (the Grok Bot). Either path runs `./run_all.sh` on the lab host and writes `report/scorecard.html` and `report/phase2-matrix.txt`.

2. **Path A — CLI on Kali.** On a Kali host, or any machine with Docker and kind, clone the repo and run `sudo ./run_all.sh`. The script apt-installs nmap, nuclei, peirates, and trivy if they are missing, creates the `kind` cluster if needed, then runs the engine tests and the Kali-tool stage.

3. **Path B — Grok Bot.** Open the [public bot template](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR), add the bot, and start a chat. The bot asks whether you have a lab host you own, clones the repo if needed, and runs `sudo ./run_all.sh` on that host.

4. **kind cluster.** The lab uses a cluster named `admission-lab`, created with kind on Docker (`kindest/node:v1.31.0` by default).

5. **Admission engines.** 13 attack pods and 1 compliant control pod are applied to each engine in turn, with only one engine installed while its results are recorded.
   - **Kyverno** is a policy engine that runs as an admission webhook. In this lab it is loaded with the restricted Pod Security Standards (PSS) policies in Enforce mode, so it rejects pods that break those rules (for example privileged containers, hostPath volumes, or running as root).
   - **OPA Gatekeeper** is also an admission webhook. It evaluates ConstraintTemplates written in Rego, Gatekeeper's policy language. This lab uses the gatekeeper-library PodSecurityPolicy templates, with constraints that deny privileged containers, hostPath volumes, host namespaces, and similar settings.
   - **Built-in Pod Security Admission (PSA)** is the API server's own controller. It is not a webhook and does not use custom rules. It is turned on with a namespace label `enforce=restricted`, and the API server itself rejects pods that fail the restricted standard.

   If the engine rejects the pod at admission time, the row is **BLOCKED** and the pod is not created. If Kubernetes accepts the pod, the row is **ADMITTED**. An ADMITTED attack pod is a gap. The compliant control pod must stay ADMITTED.

6. **Kali tools.** nmap, nuclei, peirates, and trivy then probe the live cluster. nmap scans the API and node ports, nuclei runs Kubernetes templates, peirates from a test pod tries privileged and hostPath creates plus `get-pods` and `list-secrets`, and trivy scans the images used by the pods. Output is written under `report/kali-tools/`. If a finding corresponds to a missing admission rule, the lab can write a Kyverno policy for it and re-apply that case.

7. **Generated policies, rerun, and the scorecard.** For each ADMITTED attack pod, the lab writes a Kyverno ValidatingPolicy under `policies/suggested/` and applies it. It then reapplies that attack pod to the admission engines (the `rerun attack` path in the diagram). If Kyverno now rejects it, the gap is marked `[PROVED CLOSED]`. If the compliant pod is also blocked, the new policy is too broad. The scorecard records the result: coverage, the per-engine matrix, and those proofs, in `report/scorecard.html` and `report/phase2-matrix.txt`.

## Tech Stack

| Area | Technologies |
|------|----------------|
| Cluster | Docker, [kind](https://kind.sigs.k8s.io/), Kubernetes (`kindest/node:v1.31.0` by default) |
| Cluster tooling | kubectl, Helm |
| Admission engines | [Kyverno](https://kyverno.io/) ValidatingPolicy, [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) PSP library, built-in Pod Security Admission (PSA) (`enforce=restricted`) |
| Discovery | Kali Linux — nmap, nuclei, peirates, trivy |
| Interface | CLI (`./run_all.sh`) and [Grok Bot](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) |
| Reports | Scorecard HTML/JSON, text matrix, sanitized artifacts under `report/` |

## Setup

You can start from the CLI or from the Grok Bot; both run `./run_all.sh` on the lab host. Use a disposable host you own — Kali Rolling, or any machine with Docker — and about 4 GiB of RAM so one admission engine can run at a time. Do not point this at a production, shared, or third-party cluster. The lab only tests admission when a pod is created; do not use it to compromise the host, and do not run peirates hostPath-cron. Tokens and kubeconfigs stay on the lab host. Treat generated policies as lab drafts, not production rules.

### Prerequisites

On the lab host you need:

- Docker, kind, kubectl, and Helm
- Python 3 (for the stage scripts)
- About 4 GiB of RAM
- Internet access the first time, to pull images and engine charts

`./run_all.sh` will apt-install nmap, nuclei, peirates, and trivy if they are missing.

### Path A — CLI on Kali

```bash
git clone https://github.com/ritvikindupuri/K8Admission.git
cd K8Admission
sudo ./run_all.sh
```

`LAB` defaults to the repo root. `KUBECONFIG` defaults to `~/.kube/config`.

Reports land in:

- `report/scorecard.html`
- `report/phase2-matrix.txt`
- `report/kali-tools/`

To run a stage on its own after the repo is cloned:

```bash
./scripts/setup.sh                 # kind cluster + Kyverno PSS
python3 scripts/run_phase2.py      # engine tests + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, policy re-test
```

### Path B — Grok Bot

1. Open the public bot template and add the bot: [https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR).
2. Start a chat. The getting-started skill runs first and asks, one at a time:
   - Whether you have a lab host you own and are authorized to use (a Kali host, or any machine with Docker and kind). The default is a local `kind` cluster named `admission-lab`.
   - Whether the repo is already cloned on that host.
3. If the repo is not on the host yet, clone it:

   ```bash
   git clone https://github.com/ritvikindupuri/K8Admission.git
   cd K8Admission
   ```

4. Ask the bot to run the lab, or run `sudo ./run_all.sh` yourself. The bot runs `sudo ./run_all.sh` on Kali: it installs missing tools if needed, creates the cluster if needed, then runs the engine tests and the Kali stage.

The on-repo recipe is [`template/k8admission-template.json`](template/k8admission-template.json), with [`skills/k8admission-getting-started/SKILL.md`](skills/k8admission-getting-started/SKILL.md) and [`skills/k8admission-lab/SKILL.md`](skills/k8admission-lab/SKILL.md), if you ever need to rebuild the bot by hand.

## How to Use

### Run the full lab

From the repo root on the lab host:

```bash
sudo ./run_all.sh
```

This, in order:

1. Installs nmap, nuclei, peirates, and trivy if they are missing.
2. Creates `kind` cluster `admission-lab` if it does not exist (or exports kubeconfig if it does).
3. Runs the engine tests and generates policies for whatever was admitted (`scripts/run_phase2.py`).
4. Runs the Kali-tool stage (`scripts/run_kali_stage.py`). If a finding maps to a missing admission rule, the lab can write a Kyverno policy for it and re-apply the matching pod.

### Run a single stage

Use these when you already have a cluster, or when you want to repeat one stage:

```bash
./scripts/setup.sh                 # kind + Kyverno PSS
python3 scripts/run_phase2.py      # engine tests + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, policy re-test
```

`LAB` defaults to the repo root. `KUBECONFIG` defaults to `~/.kube/config`.

### Read the scorecard and matrix

After a run, open:

| File | What it shows |
|------|----------------|
| `report/scorecard.html` | Coverage percentages, per-engine ADMITTED/BLOCKED results, and `[PROVED CLOSED]` lines, in a browser |
| `report/phase2-matrix.txt` | That matrix in plain text |
| `report/kali-tools/` | Raw and summarized nmap, nuclei, peirates, and trivy output |

How to read a result row:

- **`ADMITTED`** — the engine allowed the pod to be created. That is a gap if the row is an attack pod.
- **`BLOCKED`** — the engine rejected the pod at admission time, so it was not created.
- **`Kyverno + generated`** — results after the lab wrote and applied policies for the gaps. Attack rows that were `ADMITTED` under Kyverno, Gatekeeper, or PSA are `BLOCKED` here when the new policy holds.
- **`[PROVED CLOSED]`** — after the generated Kyverno policy was applied, that attack pod was applied again and was BLOCKED. A gap is not closed until this appears.
- **`compliant`** — the control pod. It must stay `ADMITTED` and Running after generated policies are applied. If it is blocked, a generated policy is too broad.

### Generated policies

New Kyverno ValidatingPolicies are written under `policies/suggested/` and applied to the lab cluster. Read them before you reuse them.

### Rerun

To run the full lab again on that host:

```bash
cd K8Admission
sudo ./run_all.sh
```

Before scoring Kyverno, the scripts delete leftover policies under `policies/suggested/`, so a later run is not scored against policies from an earlier run. If the `kind` cluster already exists, `./run_all.sh` reuses it. To start from a clean cluster, delete it first and then rerun:

```bash
kind delete cluster --name admission-lab
sudo ./run_all.sh
```

### Grok Bot chat flow

1. Add the bot from [https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) and start a conversation.
2. The bot introduces the lab and asks whether you have a lab host you own. If you do not, it stops.
3. If the repo is not on the lab host, clone `ritvikindupuri/K8Admission` as shown in Setup.
4. Ask it to run the lab. It runs `sudo ./run_all.sh` from the repo root, then points you at the scorecard and matrix.
5. You can also ask it to run a single stage, explain a matrix row, read a generated policy, or walk through a rerun. Tokens, kubeconfigs, and other secrets stay off the chat transcript.
6. The bot keeps these limits: admission-time testing only, no host compromise, no peirates hostPath-cron modules, and one engine at a time.

### Where results live

- The write-up of the clean lab run, including coverage, the four proved-closed gaps, and peirates outcomes, is in [TEST_RESULTS.md](TEST_RESULTS.md).
- Sanitized artifacts from that run also live under [`report/samples/`](report/samples/).
- Output from your own run is under `report/` on the lab host, as listed above.

## License

MIT. See [LICENSE](LICENSE).
