# pipeline-guard

Lightweight static analysis tool that audits GitHub Actions workflows for security misconfigurations, credential exposure, and CI/CD supply chain risks.

## Overview

Modern CI/CD pipelines frequently hold privileged access to cloud environments. `pipeline-guard` inspects workflow definitions before runtime to detect insecure permissions, long-lived credentials, and mutable action references.

## Detection Rules

| Rule ID | Severity | Category | Description & Recommended Fix |
| :--- | :--- | :--- | :--- |
| **SEC-001** | **CRITICAL** | Identity & Access | Flags static cloud credentials (`AWS_ACCESS_KEY_ID`). Recommends OIDC federation. |
| **SEC-002** | **HIGH** | Least Privilege | Flags `permissions: write-all`. Enforces granular, explicit permissions. |
| **SEC-003** | **MEDIUM** | Supply Chain | Flags mutable action tags (e.g. `@v4`). Recommends 40-character commit SHA pinning. |
| **SEC-004** | **MEDIUM** | Build Integrity | Flags non-deterministic `npm install`. Recommends `npm ci`. |

## Usage

Audit a single workflow file:
```bash
python pipeline_guard.py test_workflows/mock_vulnerable_workflow.yml
```

Audit an entire directory with structured JSON output (designed for CI/CD gates):
```bash
python pipeline_guard.py test_workflows/ --json
```

Verify a compliant workflow:
```bash
python pipeline_guard.py test_workflows/mock_secure_workflow.yml
```

## Exit Codes

- `0`: All checks passed; no policy violations detected.
- `1`: One or more security policy violations detected (or invalid target path). Automatically blocks the CI/CD pipeline from deploying insecure changes.
