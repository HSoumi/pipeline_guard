#!/usr/bin/env python3
import sys
import os
import re
import json

SEVERITY_WEIGHT = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

# Static Detection Signatures
DANGEROUS_PATTERNS = [
    {
        "id": "SEC-001",
        "severity": "CRITICAL",
        "title": "Static AWS Secret Keys in Workflow Environment",
        "regex": r"(?i)(aws[-_]?access[-_]?key[-_]?id|aws[-_]?secret[-_]?access[-_]?key)\s*:\s*\${{\s*secrets\.",
        "remediation": "Migrate from static AWS secret keys to AWS IAM OIDC Role Federation (aws-actions/configure-aws-credentials with web identity token)."
    },
    {
        "id": "SEC-002",
        "severity": "HIGH",
        "title": "Overly Permissive Workflow Permissions (write-all)",
        "regex": r"permissions\s*:\s*write-all",
        "remediation": "Declare explicit granular permissions at the top-level or job-level (e.g., contents: read, id-token: write)."
    },
    {
        "id": "SEC-003",
        "severity": "MEDIUM",
        "title": "Mutable Action Reference without Commit SHA Pinning",
        "regex": r"uses\s*:\s*[a-zA-Z0-9_\-\/]+@v[0-9]+",
        "remediation": "Pin third-party GitHub Actions to an immutable 40-character commit SHA to prevent upstream tag-hijacking."
    },
    {
        "id": "SEC-004",
        "severity": "MEDIUM",
        "title": "Non-Deterministic Package Installation (npm install)",
        "regex": r"npm\s+install(?!\s+--ignore-scripts|\s+ci)",
        "remediation": "Use 'npm ci' to enforce package-lock.json integrity and prevent unvetted transitive updates in CI."
    }
]

def scan_workflow_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        return [{"error": f"Failed to read {file_path}: {str(e)}"}]

    for line_idx, line in enumerate(lines, start=1):
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern["regex"], line):
                findings.append({
                    "rule_id": pattern["id"],
                    "severity": pattern["severity"],
                    "title": pattern["title"],
                    "file": file_path,
                    "line_number": line_idx,
                    "snippet": line.strip(),
                    "remediation": pattern["remediation"]
                })
    return findings

def sort_findings(findings):
    return sorted(findings, key=lambda x: (SEVERITY_WEIGHT.get(x.get("severity", "LOW"), 99), x.get("line_number", 0)))

def main():
    if len(sys.argv) < 2:
        print("Usage: python pipeline_guard.py <file_or_directory_path> [--json]")
        sys.exit(1)

    target_path = sys.argv[1]
    json_mode = "--json" in sys.argv

    if not os.path.exists(target_path):
        print(f"[!] Target path does not exist: {target_path}")
        sys.exit(1)

    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    files_to_scan.append(os.path.join(root, file))

    all_findings = []
    for file in files_to_scan:
        all_findings.extend(scan_workflow_file(file))

    all_findings = sort_findings(all_findings)

    if json_mode:
        print(json.dumps({
            "findings_count": len(all_findings),
            "findings": all_findings
        }, indent=2))
        sys.exit(1 if len(all_findings) > 0 else 0)

    if not all_findings:
        print("[+] No pipeline security policy violations found. CI/CD checks passed.")
        sys.exit(0)

    print(f"[!] Audit Complete: {len(all_findings)} Security Finding(s) Detected:\n")
    for f in all_findings:
        print("-" * 65)
        print(f"[{f['severity']}] {f['rule_id']}: {f['title']}")
        print(f"  Location: {f['file']}:{f['line_number']}")
        print(f"  Evidence: {f['snippet']}")
        print(f"  Fix:      {f['remediation']}")
    print("-" * 65)

    sys.exit(1)

if __name__ == "__main__":
    main()
