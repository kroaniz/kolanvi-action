"""
Kolanvi Automated Remediator
Generates precise code patches and pull request suggestions for infrastructure files.
"""

import os
from typing import List, Dict, Any

class AutoRemediator:
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root

    def generate_remediations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        patches = []

        for finding in findings:
            rule_type = finding.get("type", "")
            file_rel = finding.get("file", "")
            file_abs = os.path.join(self.workspace_root, file_rel)

            if not os.path.exists(file_abs):
                continue

            if rule_type == "CONTAINER_ROOT_EXECUTION":
                patches.append({
                    "file": file_rel,
                    "target_directive": "USER",
                    "recommended_patch": "\n# Hardened by Kolanvi: Run as unprivileged user\nUSER 10001:10001\n",
                    "description": "Enforce non-root execution policy via explicit UID assignment."
                })

            elif rule_type == "OPEN_INGRESS_PORT":
                patches.append({
                    "file": file_rel,
                    "target_directive": "ports",
                    "recommended_patch": "127.0.0.1:",
                    "description": "Restrict host port binding to loopback interface."
                })

        return patches
