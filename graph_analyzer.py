"""
Kolanvi Graph Analyzer Engine
Evaluates interdependent infrastructure vulnerabilities and calculates composite Blast Radius.
"""

from typing import List, Dict, Any

class AttackGraphAnalyzer:
    def __init__(self):
        self.base_weights = {
            "CONTAINER_ROOT_EXECUTION": 4.5,
            "OPEN_INGRESS_PORT": 3.0,
            "PRIVILEGED_MODE": 6.0,
            "SENSITIVE_MOUNT": 5.5
        }

    def calculate_blast_radius(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {
                "blast_radius_score": 0.0,
                "risk_tier": "MINIMAL",
                "attack_paths": []
            }

        score = 0.0
        finding_types = {f["type"] for f in findings}
        attack_paths = []

        # Aggregate individual baseline risk
        for item in findings:
            rule_type = item.get("type", "")
            score += self.base_weights.get(rule_type, 1.5)

        # Composite Correlation: Root execution coupled with external ingress
        if "CONTAINER_ROOT_EXECUTION" in finding_types and "OPEN_INGRESS_PORT" in finding_types:
            compound_multiplier = 1.6
            score *= compound_multiplier
            attack_paths.append({
                "vector": "Remote Exploitation to Host Takeover",
                "severity": "CRITICAL",
                "description": "Public ingress port exposed directly to a root-privileged container runtime."
            })

        # Normalize score within 0.0 - 10.0 scale
        final_score = min(round(score, 1), 10.0)

        if final_score >= 8.5:
            risk_tier = "CRITICAL"
        elif final_score >= 6.0:
            risk_tier = "HIGH"
        elif final_score >= 3.0:
            risk_tier = "MODERATE"
        else:
            risk_tier = "LOW"

        return {
            "blast_radius_score": final_score,
            "risk_tier": risk_tier,
            "attack_paths": attack_paths
        }
