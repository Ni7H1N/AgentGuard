#!/usr/bin/env python3
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any, Dict, List, Tuple

TIER_TO_SARIF_LEVEL = {"Tier 1": "error", "Tier 2": "warning", "Tier 3": "note", "Tier 4": "none"}
TIER_TO_SECURITY_SEVERITY = {"Tier 1": "9.5", "Tier 2": "7.5", "Tier 3": "5.0", "Tier 4": "2.0"}

def _parse_evidence_location(evidence: str) -> Tuple[str, int]:
    if evidence.startswith(("arn:", "entra://", "k8s://", "PID:", "http://", "https://", "ADC:")): return "agentguard-inventory.json", 1
    match = re.match(r"^([^:]+):(\d+)$", evidence.strip())
    if match: return match.group(1).lstrip("./"), max(1, int(match.group(2)))
    return evidence.strip().lstrip("./") or "agentguard-inventory.json", 1

def build_sarif_payload(nodes: List[Any], rules_config: Dict[str, Any]) -> Dict[str, Any]:
    rules_dict = rules_config.get("rules", {}); sarif_rules: List[Dict[str, Any]] = []
    for rule_id, meta in rules_dict.items():
        tier = meta.get("tier", "Tier 3")
        sarif_rules.append({"id": rule_id, "name": rule_id, "shortDescription": {"text": meta.get("primary_risk_factor", rule_id)}, "fullDescription": {"text": meta.get("description", rule_id)}, "defaultConfiguration": {"level": TIER_TO_SARIF_LEVEL.get(tier, "warning")}, "properties": {"tags": ["security", "nhi", "ai-agents", meta.get("owasp", "OWASP-NHI")], "security-severity": TIER_TO_SECURITY_SEVERITY.get(tier, "5.0"), "precision": "very-high"}})
    results: List[Dict[str, Any]] = []
    for node in nodes:
        uri, line = _parse_evidence_location(node.evidence)
        results.append({"ruleId": node.matching_rule_id or "RULE_T4_SCOPED_BASELINE", "level": TIER_TO_SARIF_LEVEL.get(node.risk_tier, "note"), "message": {"text": f"[{node.risk_tier}] {node.name} ({node.node_type}/{node.subtype}): {node.primary_risk_factor} | {node.owasp_mapping}. Blast Radius: {node.blast_radius} Remediation: {node.remediation}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}], "properties": {"identity_id": node.id, "risk_tier": node.risk_tier, "owasp_nhi": node.owasp_mapping, "is_ghost": node.is_ghost}})
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Sarif-2.1.0/rt/schemas/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "AgentGuard", "version": "0.3.0", "informationUri": "https://owasp.org/www-project-non-human-identities-top-10/", "rules": sarif_rules}}, "results": results}]}

def write_sarif_report(nodes: List[Any], output_path: str, rules_config: Dict[str, Any]) -> str:
    Path(output_path).write_text(json.dumps(build_sarif_payload(nodes, rules_config), indent=2), encoding="utf-8"); return output_path
