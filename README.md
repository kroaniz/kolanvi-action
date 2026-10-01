# 🛡️ Kolanvi Autonomous Cloud Resilience Guard

> **Autonomous Zero-Touch GitOps Remediation for Toxic Combinations across Terraform, Docker, and Application Code.**

Kolanvi correlates multi-layer attack paths (public ingress + root privileges + misconfigurations) and automatically opens hardened, test-validated GitOps Pull Requests instead of flooding developers with noisy alerts.

---

## ⚡ The Problem: Alert Fatigue vs. Attack Paths

Traditional security scanners flood pull requests with hundreds of isolated warnings. A minor code vulnerability or an open port by itself might not represent an immediate breach. 

**Kolanvi solves alert fatigue by correlating Toxic Combinations:**
> **Public Cloud Ingress (`0.0.0.0/0`)** + **Root Workload Privileges (`UID 0`)** + **Exploitable Vulnerability (CVE / Hardcoded Secret)** = **🚨 Immediate Account Takeover Vector**.

Instead of merely logging errors and blocking builds, **Kolanvi generates test-validated, hardened Pull Requests directly into your branch (Zero-Touch GitOps Remediation).**

---

## 🚀 Quickstart

Create a workflow file in your repository at `.github/workflows/kolanvi.yml`:

```yaml
name: Kolanvi Resilience Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  resilience-guard:
    name: Execute Kolanvi Attack Path Analysis
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Run Kolanvi Autonomous Guard
        id: kolanvi
        uses: kroaniz/kolanvi-action@v1.0.0
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_critical: 'true'
