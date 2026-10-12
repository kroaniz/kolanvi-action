<div align="center">
  <h1>🛡️ Kolanvi Autonomous Cloud Resilience Guard</h1>
  <p><b>Autonomous Zero-Touch GitOps Remediation for Toxic Combinations across Terraform, Docker, and Application Code.</b></p>

  [![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://kolanvi-core.onrender.com)
  [![SLSA](https://img.shields.io/badge/SLSA-Level_4_Attested-emerald?style=for-the-badge)](https://slsa.dev)
  [![License](https://img.shields.io/badge/License-Enterprise_Available-1e3a8a?style=for-the-badge)]()
</div>

---

## ⚡ The Problem: Alert Fatigue vs. Attack Paths

Traditional security scanners flood pull requests with hundreds of isolated warnings. A minor code vulnerability or an open port by itself might not represent an immediate breach. 

**Kolanvi solves alert fatigue by correlating Toxic Combinations:**
> **Public Cloud Ingress (`0.0.0.0/0`)** + **Root Workload Privileges (`UID 0`)** + **Exploitable Vulnerability (CVE / Hardcoded Secret)** = **🚨 Immediate Account Takeover Vector**.

Instead of merely logging errors and blocking builds, Kolanvi generates test-validated, hardened Pull Requests directly into your branch (Zero-Touch GitOps Remediation).

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
          target_file: 'main.tf' # Auto-detects main.tf, Dockerfile, app.py, package.json
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_critical: 'true'
          auto_pr: 'true'
          # Required for Auto-Remediation & Autonomous GitOps PRs:
          kolanvi_api_key: ${{ secrets.KOLANVI_PRO_TOKEN }}
