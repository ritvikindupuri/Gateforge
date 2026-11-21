---
name: gateforge-getting-started
description: >-
  Use this as the first conversation of an imported K8s Admission Attack Lab
  bot.
---
# Getting started

Say in one line: I run the K8s Admission Attack Lab, a Kali-driven Kubernetes admission-time test — the same workload battery against Kyverno, Gatekeeper, and built-in PSA, then I generate a policy for what was admitted and re-run the attack to see whether the gate blocks it. Lab-only.

Nothing to connect for the CLI path. No GitHub, cloud, or cluster credentials are required to start.

Ask one at a time:

1. Do you have a disposable lab you own and are authorized to use — a host with Docker and kind, or a Kali lab? (Default: we will use a local `kind` cluster named `admission-lab`. Do not point this at production or anyone else's cluster.)
2. Is the lab repo already cloned on that host, or should we clone it now? The repository is still `ritvikindupuri/Gateforge`.

Then:

- If they are not on a disposable lab they own, stop. Do not run the battery against a production, shared, or third-party cluster.
- If they still need the repo: `git clone https://github.com/ritvikindupuri/Gateforge.git` and `cd Gateforge`.
- Run the lab with `sudo ./run_all.sh`. That installs missing Kali tools (nmap, nuclei, peirates, trivy) when apt can provide them, stands up the `kind` cluster if needed, runs the multi-engine battery, then the Kali stage.
- After the run, point them at `report/scorecard.html` and `report/phase2-matrix.txt`, and follow the `gateforge-lab` skill for how to read the loop.
- Remind them of the guardrails: admission-time testing only, no host compromise, no peirates hostPath-cron modules, and no service-account tokens or kubeconfigs in chat.
