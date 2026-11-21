---
name: k8admission-lab
description: >-
  Use this when running or explaining the K8s Admission Attack Lab:
  ./run_all.sh, the three engines, Kali tools, and the closed-loop
  policy proof.
---
# K8s Admission Attack Lab workflow

Lab-only. Disposable `kind` cluster, admission-time policy testing only. Do not target production, shared, or third-party clusters. Do not compromise the host. Do not run peirates hostPath-cron or node reverse-shell modules. Do not print service-account tokens or kubeconfigs.

## Run

From the repo root on a lab host with Docker, kind, kubectl, and helm (~4 GiB RAM; one engine at a time). The GitHub repository is `ritvikindupuri/K8Admission`.

```bash
sudo ./run_all.sh
```

`LAB` defaults to the repo root. `KUBECONFIG` defaults to `~/.kube/config`. `./run_all.sh` will apt-install nmap, nuclei, peirates, and trivy if they are missing.

Stages on their own:

```bash
./scripts/setup.sh                 # kind cluster admission-lab + Kyverno PSS
python3 scripts/run_phase2.py      # multi-engine battery + generated policies
python3 scripts/run_kali_stage.py  # nmap, nuclei, peirates, trivy, loop
```

Reports land in `report/scorecard.html`, `report/phase2-matrix.txt`, and `report/kali-tools/`.

## Engines

The same 14-manifest battery, including a compliant control, is fired at each engine one at a time:

1. Kyverno restricted Pod Security Standards (Enforce)
2. OPA Gatekeeper with gatekeeper-library PSP constraints
3. Built-in Pod Security Admission (`enforce=restricted`)

Coverage is attacks blocked over attack scenarios. The compliant pod must stay admitted and Running.

## Kali tools

- nmap on 6443, 10250, 10255, 2379, and NodePorts. etcd or kubelet exposure is recorded, not turned into a Pod admission policy.
- nuclei Kubernetes templates. Stock kube-system `-code` hits are recorded, not auto-enforced.
- peirates from a test pod: `get-pods` and `list-secrets` test RBAC. Privileged and hostPath *creates* are the admission tests; this package issues those creates with in-pod `kubectl` as `kali-probe-sa` (the peirates kubectl menu is not used).
- trivy on battery images. A zero-CVE result is not a claim that the image is clean.

Mappable findings can enter the same policy generator as the battery gaps.

## Closed loop

1. Admitted attacks are gaps.
2. The lab writes Kyverno `ValidatingPolicy` (CEL) YAML under `policies/suggested/`.
3. Those policies are applied.
4. The same attack is re-run, including under a Kyverno + generated column.

A gap is closed only when the re-run is `BLOCKED` and the line says `[PROVED CLOSED]`. Generated policies are lab starting points; read them before reuse.

## How to read the scorecard

- Attack rows that were `ADMITTED` under a stock engine should be `BLOCKED` under **Kyverno + generated**.
- The `compliant` control must stay `ADMITTED` and Running after the generated policies are applied.
- Closed-loop lines should say `[PROVED CLOSED]` for each gap the generator claimed to fix.
