"""
Kolanvi Compliance Mapper
Maps infrastructure misconfigurations to SOC 2 Type II and CIS Benchmarks.
"""

from typing import List, Dict, Any

class ComplianceMapper:
    def __init__(self):
        self.control_registry = {
            "CONTAINER_ROOT_EXECUTION": {
                "soc2_control": "CC6.1 (Logical Access Controls)",
                "cis_benchmark": "CIS Docker Benchmark 4.1 (Non-root user execution)",
                "remediation_guidance": "Specify a deterministic non-root UID/GID (e.g., USER 10001:10001)."
            },
            "OPEN_INGRESS_PORT": {
                "soc2_control": "CC6.6 (Boundary Protection & Network Perimeter)",
                "cis_benchmark": "CIS Docker Benchmark 5.13 (Restrict incoming traffic to local loopback)",
                "remediation_guidance": "Bind listening ports explicitly to 127.0.0.1 or private service networks."
            }
        }

    def map_violations_to_soc2(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        controls_evaluated = []
        non_compliant_count = 0

        for finding in findings:
            rule_type = finding.get("type", "")
            mapping = self.control_registry.get(rule_type)
            if mapping:
                non_compliant_count += 1
                controls_evaluated.append({
                    "rule": rule_type,
                    "file": finding.get("file", "unknown"),
                    "control_id": mapping["soc2_control"],
                    "cis_id": mapping["cis_benchmark"],
                    "status": "NON_COMPLIANT",
                    "remediation": mapping["remediation_guidance"]
                })

        overall_status = "AUDIT_FAILED" if non_compliant_count > 0 else "AUDIT_READY"

        return {
            "status": overall_status,
            "non_compliant_count": non_compliant_count,
            "controls": controls_evaluated
        }
