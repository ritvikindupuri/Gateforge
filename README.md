<p align="center">
  <img src="assets/icons/kubernetes.png" alt="K8s Admission Attack Lab" width="80">
</p>

<h1 align="center">K8s Admission Attack Lab</h1>

<p align="center"><strong>K8Admission</strong></p>

<p align="center">A disposable lab that checks whether Kubernetes admission controllers block the attack at deploy time</p>

The K8s Admission Attack Lab is a Kali-driven, admission-time test for Kubernetes. It fires the same 14-manifest battery at Kyverno, OPA Gatekeeper, and built-in Pod Security Admission, one engine at a time, on a disposable `kind` cluster. Whatever a stock gate admits becomes a Kyverno ValidatingPolicy, and the same attack is re-run until the webhook blocks it.

This is a policy-gate test, not a runtime detect-and-remediate tool. Use it only on a disposable cluster you own. Admission-time testing only — no host compromise, and no peirates hostPath-cron. Run one engine at a time (~4 GiB RAM). Tokens and kubeconfigs stay on the lab host. Generated policies are lab starting points, not production drop-ins.

## Key Features

- **Multi-engine battery.** The same 14 workloads, including a compliant control, are applied to Kyverno (restricted PSS, Enforce), OPA Gatekeeper (PSP library), and built-in PSA (`enforce=restricted`), one engine at a time.
- **Closed-loop proof.** Admitted attacks are turned into Kyverno ValidatingPolicies, applied, and re-fired at the live webhook until the result is `BLOCKED` and marked `[PROVED CLOSED]`.
- **Kali-tool discovery.** nmap, nuclei, peirates, and trivy probe the live cluster. Mappable findings can enter the same policy generator.
- **Two ways in.** Run the CLI on Kali (or any Docker/kind host), or drive the same lab from the Grok Bot.
- **Scorecard and matrix.** Side-by-side coverage, closed-loop proofs, and HTML/JSON reports under `report/`.
- **Lab-only by design.** Targets a disposable `kind` cluster named `admission-lab`. Not for production, shared, or third-party clusters.

## System Architecture

<p align="center">
  <img src="assets/architecture.png" alt="System architecture of the K8s Admission Attack Lab" width="800">
</p>

1. **You** start the lab from either path below. Both drive the same pipeline.
2. **Path A — CLI on Kali.** On a disposable Kali host (or any machine with Docker and kind), clone the repo and run `sudo ./run_all.sh`. The script installs missing Kali tools, stands up the cluster if needed, and runs the loop.
3. **Path B — Grok Bot.** Add the bot from the [public template](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) and ask it to drive the same lab on Kali.
4. Both paths use a disposable **kind** cluster (`admission-lab`) running on **Docker**.
5. **Admission engines** — Kyverno, OPA Gatekeeper, and built-in PSA — each see the same 14-manifest battery, one at a time. **Kali tools** (nmap, nuclei, peirates, trivy) probe the live cluster.
6. Admitted attacks become **generated policies**. The same attack is re-run until the webhook blocks it. The **scorecard** records coverage and closed-loop proofs.

## Tech Stack

| Area | Technologies |
|------|----------------|
| Cluster | Docker, [kind](https://kind.sigs.k8s.io/), Kubernetes (`kindest/node:v1.31.0` by default) |
| Cluster tooling | kubectl, Helm |
| Admission engines | [Kyverno](https://kyverno.io/) ValidatingPolicy, [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) PSP library, built-in Pod Security Admission (`enforce=restricted`) |
| Discovery | Kali Linux — nmap, nuclei, peirates, trivy |
| Interface | CLI (`./run_all.sh`) and [Grok Bot](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) |
| Reports | Scorecard HTML/JSON, text matrix, sanitized samples under `report/` |

## Setup Instructions

There are two ways in, and they run the same lab. Use a disposable host you own — Kali Rolling, or any machine with Docker — and about 4 GiB of RAM so one admission engine can run at a time. Do not point this at a production, shared, or third-party cluster.

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
python3 scripts/run_phase2.py      # multi-engine battery + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, loop
```

### Path B — Grok Bot

1. Open the public bot template and add the bot: [https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR).
2. Start a chat. The getting-started skill runs first and will ask, one at a time:
   - Whether you have a disposable lab you own and are authorized to use (a Kali host, or any machine with Docker and kind). The default is a local `kind` cluster named `admission-lab`.
   - Whether the repo is already cloned on that host.
3. If the repo is not on the host yet, clone it:

   ```bash
   git clone https://github.com/ritvikindupuri/K8Admission.git
   cd K8Admission
   ```

4. Ask the bot to run the lab (or run it yourself with `sudo ./run_all.sh`). The bot drives the same CLI path on Kali: missing tools are installed if needed, the cluster is created if needed, then the multi-engine battery and the Kali stage run.

The on-repo recipe is [`template/k8admission-template.json`](template/k8admission-template.json), with [`skills/k8admission-getting-started/SKILL.md`](skills/k8admission-getting-started/SKILL.md) and [`skills/k8admission-lab/SKILL.md`](skills/k8admission-lab/SKILL.md), if you ever need to rebuild the bot by hand.

## Usage Guide

### Run the full lab

From the repo root on the lab host:

```bash
sudo ./run_all.sh
```

This, in order:

1. Installs nmap, nuclei, peirates, and trivy if they are missing.
2. Creates `kind` cluster `admission-lab` if it does not exist (or exports kubeconfig if it does).
3. Runs the multi-engine battery and generates policies for whatever was admitted (`scripts/run_phase2.py`).
4. Runs the Kali-tool stage and feeds mappable findings into the same loop (`scripts/run_kali_stage.py`).

### Run a single stage

Use these when you already have a cluster, or when you want to repeat one part of the loop:

```bash
./scripts/setup.sh                 # kind + Kyverno PSS
python3 scripts/run_phase2.py      # multi-engine battery + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, loop
```

`LAB` defaults to the repo root. `KUBECONFIG` defaults to `~/.kube/config`.

### Read the scorecard and matrix

After a run, open:

| File | What it shows |
|------|----------------|
| `report/scorecard.html` | Coverage percentages, per-engine results, and closed-loop proofs in a browser |
| `report/phase2-matrix.txt` | The same matrix in plain text |
| `report/kali-tools/` | Raw and summarized nmap, nuclei, peirates, and trivy output |

How to read a result row:

- **`ADMITTED`** — the engine allowed the workload to deploy. That is a gap if the row is an attack scenario.
- **`BLOCKED`** — the admission webhook rejected the workload.
- **`Kyverno + generated`** — after the lab wrote and applied policies for the gaps. Attack rows that were `ADMITTED` under a stock engine should be `BLOCKED` here.
- **`[PROVED CLOSED]`** — the same attack was re-run against the live webhook and was blocked. A gap is not closed until this appears.
- **`compliant`** — the control workload. It must stay `ADMITTED` and Running after generated policies are applied. If it is blocked, a generated policy is too broad.

Coverage is attacks blocked divided by attack scenarios (13 in the battery). The compliant control is not counted as an attack.

### Generated policies

New Kyverno ValidatingPolicies are written under `policies/suggested/` and applied to the lab cluster. Read them before you reuse them. They are starting points from this lab, not production drop-ins.

### Rerun

To run the full loop again on the same host:

```bash
cd K8Admission
sudo ./run_all.sh
```

The harness clears leftover suggested policies before it scores stock Kyverno, so a later run does not inherit the previous loop’s closes. If the `kind` cluster already exists, `./run_all.sh` reuses it. To start from a clean cluster, delete it first and then rerun:

```bash
kind delete cluster --name admission-lab
sudo ./run_all.sh
```

### Grok Bot chat flow

1. Add the bot from [https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR](https://x.ai/bot/jOM5_aaw8G0b9kSWHoYDR) and start a conversation.
2. The bot introduces the lab and asks whether you have a disposable cluster you own. If you do not, it should stop. Do not ask it to target production or anyone else’s cluster.
3. If the repo is not on the lab host, clone `ritvikindupuri/K8Admission` as shown in Setup.
4. Ask it to run the lab. It should prefer `sudo ./run_all.sh` from the repo root, then point you at the scorecard and matrix.
5. You can also ask it to run a single stage, explain a matrix row, read a generated policy, or walk through a rerun. Tokens, kubeconfigs, and other secrets must stay off the chat transcript.
6. Guardrails the bot is expected to keep: admission-time testing only, no host compromise, no peirates hostPath-cron modules, one engine at a time.

### Where results live

- A written assessment of a disposable run, including coverage, proved-closed gaps, and peirates outcomes, is in [TEST_RESULTS.md](TEST_RESULTS.md).
- Sanitized artifacts from that work also live under [`report/samples/`](report/samples/).
- Live output from *your* run is under `report/` on the lab host, as listed above.

## License

MIT. See [LICENSE](LICENSE).

This lab is for disposable clusters you own. Do not run it against production, shared, or third-party clusters.
