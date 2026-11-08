#!/usr/bin/env python3
"""
AgentGuard v0.3: Deterministic Discovery & Risk Scanner for AI Agents and Non-Human Identities (NHIs).
Maps findings to the OWASP Non-Human Identities Top 10 (2025).
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional third-party imports with graceful fallback
try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

try:
    import boto3
except ImportError:
    boto3 = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    from kubernetes import client as k8s_client, config as k8s_config
except ImportError:
    k8s_client = None  # type: ignore
    k8s_config = None  # type: ignore

# Local v0.3 modules
try:
    from agentguard_sarif import write_sarif_report
except ImportError:
    write_sarif_report = None  # type: ignore

try:
    from mcp_sse_probe import MCPSSEProbe
except ImportError:
    MCPSSEProbe = None  # type: ignore

try:
    from agentguard_graph_export import render_dot, render_mermaid, write_graph_export
except ImportError:
    render_dot = None  # type: ignore
    render_mermaid = None  # type: ignore
    write_graph_export = None  # type: ignore


# =====================================================================
# OWASP Non-Human Identities Top 10 (2025) Mapping Constants
# =====================================================================
OWASP_NHI_2025 = {
    "NHI1": "NHI1:2025 - Improper Offboarding",
    "NHI2": "NHI2:2025 - Secret Leakage",
    "NHI3": "NHI3:2025 - Vulnerable Third-Party NHI",
    "NHI4": "NHI4:2025 - Insecure Authentication",
    "NHI5": "NHI5:2025 - Overprivileged NHI",
    "NHI6": "NHI6:2025 - Insecure Cloud Deployment Configurations",
    "NHI7": "NHI7:2025 - Long-Lived Secrets",
    "NHI8": "NHI8:2025 - Environment Isolation",
    "NHI9": "NHI9:2025 - NHI Reuse",
    "NHI10": "NHI10:2025 - Human Use of NHI",
}


# =====================================================================
# External Rule Configuration Loader (rules.yaml with safe fallback)
# =====================================================================
DEFAULT_RULES_CONFIG: Dict[str, Any] = {
    "version": "0.3",
    "thresholds": {
        "rotation_max_age_days": 90,
        "admin_min_aggravators": 2,
    },
    "rules": {
        "RULE_T1_GHOST_AGENT": {
            "enabled": True,
            "tier": "Tier 1",
            "owasp": "NHI1",
            "primary_risk_factor": "Untracked Ghost Agent (Shadow AI Runtime)",
            "description": "Active agent or MCP process running in memory with no matching source manifest or owner.",
        },
        "RULE_T1_HARDCODED_SECRET": {
            "enabled": True,
            "tier": "Tier 1",
            "owasp": "NHI2",
            "primary_risk_factor": "Hardcoded Plaintext Secret",
            "description": "Identity or agent uses a static, plaintext secret embedded directly in source code or config.",
        },
        "RULE_T1_WILDCARD_EXPOSED": {
            "enabled": True,
            "tier": "Tier 1",
            "owasp": "NHI5",
            "primary_risk_factor": "Wildcard Privilege + Exposure/Governance Aggravator",
            "description": "Identity holds 'wildcard' privileges combined with at least one aggravator (public exposure, full autonomy, long-lived key, or orphaned owner).",
        },
        "RULE_T1_ADMIN_MULTI_AGGRAVATOR": {
            "enabled": True,
            "tier": "Tier 1",
            "owasp": "NHI5",
            "primary_risk_factor": "Admin Privilege + Multiple High-Risk Aggravators",
            "description": "Identity holds 'admin' privileges combined with two or more high-risk aggravators (public exposure, full autonomy, long-lived credential, or orphaned owner).",
        },
        "RULE_T2_ORPHANED_IDENTITY": {
            "enabled": True,
            "tier": "Tier 2",
            "owasp": "NHI1",
            "primary_risk_factor": "Orphaned Identity (Missing or Departed Owner)",
            "description": "Owner metadata is missing, inactive, or departed, leaving identity ungoverned.",
        },
        "RULE_T2_UNROTATED_LONG_LIVED_KEY": {
            "enabled": True,
            "tier": "Tier 2",
            "owasp": "NHI7",
            "primary_risk_factor": "Unrotated Long-Lived Credential",
            "description": "Long-lived credential has exceeded the maximum rotation age threshold.",
        },
        "RULE_T2_NHI_REUSE": {
            "enabled": True,
            "tier": "Tier 2",
            "owasp": "NHI9",
            "primary_risk_factor": "Cross-Workload NHI Reuse",
            "description": "Multiple distinct agents or workloads share the same underlying NHI or secret credential.",
        },
        "RULE_T3_ELEVATED_OR_STATIC_AUTH": {
            "enabled": True,
            "tier": "Tier 3",
            "owasp": "NHI4",
            "primary_risk_factor": "Write/Admin Privilege or Static Auth",
            "description": "Identity has write/admin permissions (below Tier 1 multi-aggravator threshold) or uses static authentication.",
        },
        "RULE_T4_SCOPED_BASELINE": {
            "enabled": True,
            "tier": "Tier 4",
            "owasp": "NHI6",
            "primary_risk_factor": "Scoped & Governed (Baseline Risk)",
            "description": "Scoped privileges, short-lived credentials, internal exposure, and active ownership verified.",
        },
    },
}


def load_rules_config(config_path: str = "rules.yaml") -> Dict[str, Any]:
    """Loads rules.yaml if present and valid; otherwise falls back to DEFAULT_RULES_CONFIG."""
    cfg = json.loads(json.dumps(DEFAULT_RULES_CONFIG))
    path = Path(config_path)
    if path.exists() and yaml is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                if "thresholds" in loaded and isinstance(loaded["thresholds"], dict):
                    cfg["thresholds"].update(loaded["thresholds"])
                if "rules" in loaded and isinstance(loaded["rules"], dict):
                    for r_id, r_val in loaded["rules"].items():
                        if r_id in cfg["rules"] and isinstance(r_val, dict):
                            cfg["rules"][r_id].update(r_val)
                        elif isinstance(r_val, dict):
                            cfg["rules"][r_id] = r_val
        except Exception as exc:
            print(f"[!] Warning: Failed to parse {config_path} ({exc}); using safe built-in defaults.", file=sys.stderr)
    return cfg


# =====================================================================
# Data Models
# =====================================================================
@dataclass
class Node:
    id: str
    name: str
    node_type: str  # AGENT | NHI | SECRET | MCP_SERVER | RESOURCE
    subtype: str    # e.g., LangChain, CrewAI, AWS_IAM_ROLE, K8S_SA, GITHUB_TOKEN
    evidence: str   # file:line, ARN, PID, etc.
    privilege_level: str = "scoped"        # wildcard | admin | write | read | scoped
    credential_type: str = "short-lived"   # hardcoded | long-lived | short-lived | none
    rotation_age_days: int = 0
    owner: Optional[str] = None
    owner_status: str = "active"           # active | inactive | missing | departed
    network_exposure: str = "internal"     # public | internal | local
    autonomy_level: str = "N/A"            # fully_autonomous | interactive | tool_calling | N/A
    is_ghost: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Populated by Tiering Engine
    risk_tier: str = "Tier 4"
    primary_risk_factor: str = ""
    matching_rule_id: str = ""
    matching_rule_desc: str = ""
    owasp_mapping: str = ""
    blast_radius: str = ""
    remediation: str = ""


@dataclass
class Edge:
    source: str
    target: str
    relation: str  # can_assume | can_read | can_write | owns | has_secret


class IdentityGraph:
    """In-memory directed graph representing Agents, NHIs, Secrets, MCP servers, and Resources."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node) -> None:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        else:
            existing = self.nodes[node.id]
            existing.metadata.update(node.metadata)

    def add_edge(self, source: str, target: str, relation: str) -> None:
        edge = Edge(source=source, target=target, relation=relation)
        if edge not in self.edges:
            self.edges.append(edge)

    def get_outgoing(self, node_id: str) -> List[Tuple[Edge, Optional[Node]]]:
        return [(e, self.nodes.get(e.target)) for e in self.edges if e.source == node_id]

    def get_incoming(self, node_id: str) -> List[Tuple[Edge, Optional[Node]]]:
        return [(e, self.nodes.get(e.source)) for e in self.edges if e.target == node_id]

    def detect_orphaned_identities(self) -> None:
        """Flag NHIs, Agents, and MCP servers whose human owner is missing, inactive, or departed."""
        for node in self.nodes.values():
            if node.node_type in ("NHI", "AGENT", "MCP_SERVER"):
                if not node.owner or node.owner.strip() == "" or node.owner.lower() in ("unknown", "none", "unassigned"):
                    node.owner_status = "missing"
                elif any(tag in node.owner.lower() for tag in ("[inactive]", "[departed]", "disabled", "offboarded", "former")):
                    node.owner_status = "departed"

    def detect_secret_reuse(self) -> Set[str]:
        """
        Return node IDs of secrets/NHIs reused across multiple consumers OR any consumers
        that share the same underlying secret/NHI.
        """
        inbound_sources: Dict[str, Set[str]] = {}
        for edge in self.edges:
            if edge.relation in ("has_secret", "can_assume"):
                inbound_sources.setdefault(edge.target, set()).add(edge.source)

        reused_nodes: Set[str] = set()
        for target, sources in inbound_sources.items():
            if len(sources) > 1:
                reused_nodes.add(target)
                reused_nodes.update(sources)
        return reused_nodes


# =====================================================================
# 1. Discovery Engine: Static Repository Collector
# =====================================================================
class RepoCollector:
    """
    Scans local repository for AI agent frameworks, MCP configs, and hardcoded secrets.
    Includes v0.2/v0.3 fixes:
      - Bug #1 Fix: Deduplicates agent node creation per (file, framework).
      - Bug #3 Fix: Supports unquoted .env secrets in addition to quoted strings.
      - Bug #6 Fix: Cross-file secret reuse links all agents in the repository to shared
        .env / config secrets or identical secret fingerprints across files.
    """

    AGENT_PATTERNS = {
        "LangChain": [
            r"from\s+langchain",
            r"import\s+langchain",
            r"initialize_agent\s*\(",
            r"create_react_agent\s*\(",
            r"AgentExecutor\s*\(",
            r"ChatOpenAI\s*\(",
        ],
        "CrewAI": [
            r"from\s+crewai\s+import",
            r"import\s+crewai",
            r"\bCrew\s*\(",
            r"\bAgent\s*\(\s*role=",
        ],
        "AutoGen": [
            r"from\s+autogen\s+import",
            r"import\s+autogen",
            r"ConversableAgent\s*\(",
            r"AssistantAgent\s*\(",
            r"UserProxyAgent\s*\(",
        ],
        "PydanticAI": [
            r"from\s+pydantic_ai\s+import",
            r"import\s+pydantic_ai",
            r"Agent\s*\(\s*['\"][\w\-]+:",
        ],
        "OpenAI_Client": [
            r"from\s+openai\s+import\s+OpenAI",
            r"client\s*=\s*OpenAI\s*\(",
        ],
        "Anthropic_Client": [
            r"from\s+anthropic\s+import\s+Anthropic",
            r"client\s*=\s*Anthropic\s*\(",
        ],
    }

    SECRET_PATTERNS = [
        ("OpenAI_API_Key", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"),
        ("Anthropic_API_Key", r"\b(sk-ant-api03-[A-Za-z0-9_\-]{20,})\b"),
        ("AWS_Access_Key", r"\b(AKIA[0-9A-Z]{16})\b"),
        ("GitHub_PAT", r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"),
        ("Slack_Bot_Token", r"\b(xox[baprs]-[0-9a-zA-Z\-]{10,})\b"),
        ("Generic_Bearer_Key", r"(?i)(?:api_key|secret_key|access_token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{24,})['\"]?"),
    ]

    MODEL_ENDPOINT_REGEX = re.compile(
        r"(?:model|model_name|base_url|endpoint)\s*=\s*['\"]([^'\"]+)['\"]"
    )
    AUTONOMY_HINTS_REGEX = re.compile(
        r"(?:human_input_mode\s*=\s*['\"]NEVER['\"]|allow_delegation\s*=\s*True|code_execution_config\s*=\s*\{[^}]*\}|yolo\s*=\s*True)"
    )

    def __init__(self, repo_path: str, graph: IdentityGraph) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.graph = graph
        self.discovered_agent_files: Set[str] = set()
        self._repo_agent_ids: List[str] = []
        self._env_secret_ids: List[str] = []
        self._agent_env_var_refs: Dict[str, Set[str]] = {}
        self._env_var_to_secret_id: Dict[str, str] = {}

    @staticmethod
    def _fingerprint(raw_secret: str) -> str:
        digest = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()[:10]
        prefix = raw_secret[:6] if len(raw_secret) >= 6 else "secret"
        return f"{prefix}...[sha256:{digest}]"

    def collect(self) -> None:
        if not self.repo_path.exists():
            print(f"[!] Warning: Repo path {self.repo_path} does not exist.", file=sys.stderr)
            return

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "__pycache__"}]
            for fname in sorted(files):
                fpath = Path(root) / fname
                rel_path = fpath.relative_to(self.repo_path).as_posix()

                if fname.endswith(".py"):
                    self._scan_python_file(fpath, rel_path)
                elif (
                    fname in ("mcp.json", "claude_desktop_config.json", ".cursorrules", "mcp_servers.json", ".env")
                    or fname.startswith(".env.")
                    or fname.endswith((".env", ".yaml", ".yml", ".json"))
                ):
                    self._scan_config_file(fpath, rel_path)

        for ag_id in self._repo_agent_ids:
            referenced_vars = self._agent_env_var_refs.get(ag_id, set())
            for env_key, sec_id in self._env_var_to_secret_id.items():
                if env_key in referenced_vars or "*" in referenced_vars:
                    self.graph.add_edge(ag_id, sec_id, "has_secret")
                    self.graph.nodes[ag_id].credential_type = "hardcoded"

    def _scan_python_file(self, fpath: Path, rel_path: str) -> None:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        lines = content.splitlines()
        file_agents: List[str] = []

        for framework, patterns in self.AGENT_PATTERNS.items():
            first_match_line: Optional[int] = None
            for idx, line in enumerate(lines, start=1):
                if any(re.search(pat, line) for pat in patterns):
                    first_match_line = idx
                    break

            if first_match_line is not None:
                agent_id = f"agent:{rel_path}:{framework}:{first_match_line}"
                autonomy = "fully_autonomous" if self.AUTONOMY_HINTS_REGEX.search(content) else "tool_calling"
                endpoints = self.MODEL_ENDPOINT_REGEX.findall(content)
                tools_found = self._extract_ast_tools(content)

                priv = "admin" if any(t in ("bash", "shell", "sql_db", "python_repl", "exec") for t in tools_found) else "write"
                node = Node(
                    id=agent_id,
                    name=f"{framework}_Agent ({Path(rel_path).stem})",
                    node_type="AGENT",
                    subtype=framework,
                    evidence=f"{rel_path}:{first_match_line}",
                    privilege_level=priv,
                    credential_type="short-lived",
                    owner=self._extract_code_owner(content),
                    autonomy_level=autonomy,
                    metadata={
                        "model_endpoints": list(set(endpoints)) or ["default_endpoint"],
                        "tools": tools_found,
                        "source_file": str(fpath.resolve()),
                        "rel_path": rel_path,
                    },
                )
                self.graph.add_node(node)
                file_agents.append(agent_id)
                self._repo_agent_ids.append(agent_id)
                self.discovered_agent_files.add(rel_path)
                self.discovered_agent_files.add(str(fpath.resolve()))
                self.discovered_agent_files.add(fpath.name)

                env_refs = set(re.findall(r"(?:os\.getenv|os\.environ\.get)\s*\(\s*['\"]([A-Za-z0-9_]+)['\"]", content))
                env_refs.update(re.findall(r"os\.environ\[\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]", content))
                if "load_dotenv" in content:
                    env_refs.add("*")
                self._agent_env_var_refs[agent_id] = env_refs

        for sec_type, sec_regex in self.SECRET_PATTERNS:
            for idx, line in enumerate(lines, start=1):
                match = re.search(sec_regex, line)
                if match:
                    raw_val = match.group(1) if match.groups() else match.group(0)
                    fp = self._fingerprint(raw_val)
                    sec_id = f"secret:{fp}"
                    if sec_id not in self.graph.nodes:
                        sec_node = Node(
                            id=sec_id,
                            name=f"{sec_type} ({fp})",
                            node_type="SECRET",
                            subtype=sec_type,
                            evidence=f"{rel_path}:{idx}",
                            privilege_level="write",
                            credential_type="hardcoded",
                            rotation_age_days=365,
                            owner=None,
                            metadata={"redacted_fingerprint": fp, "locations": [f"{rel_path}:{idx}"]},
                        )
                        self.graph.add_node(sec_node)
                    else:
                        locs = self.graph.nodes[sec_id].metadata.setdefault("locations", [])
                        loc_str = f"{rel_path}:{idx}"
                        if loc_str not in locs:
                            locs.append(loc_str)

                    for ag_id in file_agents:
                        self.graph.add_edge(ag_id, sec_id, "has_secret")
                        self.graph.nodes[ag_id].credential_type = "hardcoded"

    def _extract_ast_tools(self, content: str) -> List[str]:
        tools: List[str] = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for dec in node.decorator_list:
                        dec_name = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                        if "tool" in dec_name.lower():
                            tools.append(node.name)
                elif isinstance(node, ast.Call):
                    func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
                    if any(k in func_name for k in ("ShellTool", "PythonREPLTool", "SQLDatabaseToolkit")):
                        tools.append(func_name.lower())
        except SyntaxError:
            pass
        return list(set(tools))

    @staticmethod
    def _extract_code_owner(content: str) -> Optional[str]:
        match = re.search(r"@owner:\s*([^\n\r]+)", content, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _scan_config_file(self, fpath: Path, rel_path: str) -> None:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        if fpath.name.endswith(".json") and "mcpServers" in content:
            try:
                data = json.loads(content)
                mcp_servers = data.get("mcpServers", {})
                for srv_name, srv_cfg in mcp_servers.items():
                    mcp_id = f"mcp:{rel_path}:{srv_name}"
                    cmd = srv_cfg.get("command", "")
                    args = " ".join(srv_cfg.get("args", []))
                    env_vars = srv_cfg.get("env", {})
                    has_hardcoded_env = any(len(str(v)) > 12 and not str(v).startswith("$") for v in env_vars.values())

                    mcp_node = Node(
                        id=mcp_id,
                        name=f"MCP_Server:{srv_name}",
                        node_type="MCP_SERVER",
                        subtype="ModelContextProtocol",
                        evidence=f"{rel_path}",
                        privilege_level="admin" if ("filesystem" in args or "postgres" in args or "docker" in cmd) else "write",
                        credential_type="hardcoded" if has_hardcoded_env else "short-lived",
                        network_exposure="public" if "0.0.0.0" in args or "sse" in args else "local",
                        autonomy_level="tool_calling",
                        metadata={"command": cmd, "args": args, "env_keys": list(env_vars.keys())},
                    )
                    self.graph.add_node(mcp_node)
            except json.JSONDecodeError:
                pass

        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            env_var_match = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stripped)
            env_var_name = env_var_match.group(1) if env_var_match else None

            for sec_type, sec_regex in self.SECRET_PATTERNS:
                match = re.search(sec_regex, stripped)
                if match:
                    raw_val = match.group(1) if match.groups() else match.group(0)
                    fp = self._fingerprint(raw_val)
                    sec_id = f"secret:{fp}"
                    if sec_id not in self.graph.nodes:
                        self.graph.add_node(
                            Node(
                                id=sec_id,
                                name=f"{sec_type} ({fp})",
                                node_type="SECRET",
                                subtype=sec_type,
                                evidence=f"{rel_path}:{idx}",
                                privilege_level="write",
                                credential_type="hardcoded",
                                rotation_age_days=365,
                                metadata={"redacted_fingerprint": fp, "locations": [f"{rel_path}:{idx}"]},
                            )
                        )
                    self._env_secret_ids.append(sec_id)
                    if env_var_name:
                        self._env_var_to_secret_id[env_var_name] = sec_id
                    break


# =====================================================================
# 2. Discovery Engine: Runtime Process & Ghost Agent Inspector
# =====================================================================
class RuntimeCollector:
    """
    Inspects live process table and sockets; flags untracked processes as GHOST agents.
    Normalizes absolute, relative, module (`-m pkg.mod`), and basename paths.
    """

    RUNTIME_SIGNATURES = {
        "LangChain": re.compile(r"(langchain|langserve|langgraph)", re.I),
        "CrewAI": re.compile(r"(crewai|crew_runner)", re.I),
        "AutoGen": re.compile(r"(autogen|autogenstudio)", re.I),
        "PydanticAI": re.compile(r"(pydantic_ai|pydantic-ai)", re.I),
        "MCP_Server": re.compile(r"(@modelcontextprotocol|mcp-server|mcp_server)", re.I),
    }

    def __init__(self, graph: IdentityGraph, known_source_files: Set[str]) -> None:
        self.graph = graph
        self.known_source_files = known_source_files

    def _matches_known_source(self, cmdline: str) -> bool:
        if not self.known_source_files:
            return False

        cmd_norm = cmdline.replace("\\", "/")
        for src in self.known_source_files:
            src_norm = src.replace("\\", "/")
            src_path = Path(src_norm)
            basename = src_path.name
            module_notation = src_norm.removesuffix(".py").replace("/", ".")
            if (
                src_norm in cmd_norm
                or basename in cmd_norm
                or (module_notation and module_notation in cmd_norm)
            ):
                return True
        return False

    def collect(self, synthetic_procs: Optional[List[Dict[str, Any]]] = None) -> None:
        procs = synthetic_procs if synthetic_procs is not None else self._get_live_processes()
        for proc in procs:
            pid = proc["pid"]
            cmdline = proc["cmdline"]
            listen_public = proc.get("public_socket", False)

            matched_known = self._matches_known_source(cmdline)

            for sig_name, regex in self.RUNTIME_SIGNATURES.items():
                if regex.search(cmdline) or matched_known:
                    is_ghost = not matched_known
                    node_id = f"runtime:pid:{pid}"
                    node = Node(
                        id=node_id,
                        name=f"Runtime_{sig_name} (PID {pid})",
                        node_type="AGENT" if sig_name != "MCP_Server" else "MCP_SERVER",
                        subtype=sig_name,
                        evidence=f"PID:{pid} cmd='{cmdline[:80]}'",
                        privilege_level="admin" if "--allow-root" in cmdline or "--privileged" in cmdline else "write",
                        credential_type="long-lived",
                        owner=proc.get("user") if not is_ghost else None,
                        owner_status="missing" if is_ghost else "active",
                        network_exposure="public" if listen_public or "0.0.0.0" in cmdline else "internal",
                        autonomy_level="fully_autonomous" if is_ghost else "tool_calling",
                        is_ghost=is_ghost,
                        metadata={"pid": pid, "cmdline": cmdline},
                    )
                    self.graph.add_node(node)
                    break

    @staticmethod
    def _get_live_processes() -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            out = subprocess.check_output(["ps", "-eo", "pid,user,args"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    results.append({"pid": parts[0], "user": parts[1], "cmdline": parts[2], "public_socket": False})
        except Exception:
            pass
        return results


# =====================================================================
# 3. Discovery Engine: Cloud IAM Collectors
# =====================================================================
class CloudCollector:
    """
    Read-only collectors for AWS IAM, Microsoft Entra ID (Azure AD), and GCP IAM.
    Derives actual attached/inline user and group IAM policies for AWS Access Keys.
    """

    def __init__(self, provider: str, graph: IdentityGraph) -> None:
        self.provider = provider.lower()
        self.graph = graph

    def collect(self) -> None:
        if self.provider == "aws":
            self._collect_aws_iam()
        elif self.provider == "azure":
            self._collect_entra_id()
        elif self.provider == "gcp":
            self._collect_gcp_iam()

    @staticmethod
    def _derive_aws_user_privilege(iam_client: Any, username: str) -> str:
        policy_names: List[str] = []
        try:
            attached = iam_client.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            policy_names.extend(p["PolicyName"] for p in attached)

            inline = iam_client.list_user_policies(UserName=username).get("PolicyNames", [])
            policy_names.extend(inline)

            groups = iam_client.list_groups_for_user(UserName=username).get("Groups", [])
            for grp in groups:
                gname = grp["GroupName"]
                g_att = iam_client.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
                policy_names.extend(p["PolicyName"] for p in g_att)
        except Exception:
            return "scoped"

        for pname in policy_names:
            if "AdministratorAccess" in pname:
                return "wildcard"
            if "FullAccess" in pname or "PowerUserAccess" in pname or "Admin" in pname:
                return "admin"
            if "Write" in pname or "Put" in pname:
                return "write"
            if "ReadOnly" in pname or "ViewOnly" in pname:
                return "read"
        return "scoped"

    def _collect_aws_iam(self) -> None:
        if boto3 is None:
            print("[!] boto3 not installed; skipping live AWS IAM collection.", file=sys.stderr)
            return

        try:
            iam = boto3.client("iam")
            now = datetime.datetime.now(datetime.timezone.utc)

            roles = iam.list_roles().get("Roles", [])
            for role in roles:
                role_name = role["RoleName"]
                arn = role["Arn"]
                trust_doc = json.dumps(role.get("AssumeRolePolicyDocument", {}))
                is_wildcard_trust = '"AWS": "*"' in trust_doc

                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                priv = "scoped"
                for pol in attached:
                    if "AdministratorAccess" in pol["PolicyName"]:
                        priv = "wildcard"
                        break
                    if "FullAccess" in pol["PolicyName"]:
                        priv = "admin"

                node_id = f"nhi:aws:role:{role_name}"
                self.graph.add_node(
                    Node(
                        id=node_id,
                        name=role_name,
                        node_type="NHI",
                        subtype="AWS_IAM_Role",
                        evidence=arn,
                        privilege_level=priv,
                        credential_type="short-lived",
                        network_exposure="public" if is_wildcard_trust else "internal",
                        metadata={"arn": arn, "wildcard_trust": is_wildcard_trust},
                    )
                )

            users = iam.list_users().get("Users", [])
            for user in users:
                uname = user["UserName"]
                u_arn = user["Arn"]
                user_priv = self._derive_aws_user_privilege(iam, uname)
                keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                for k in keys:
                    if k["Status"] == "Active":
                        age_days = (now - k["CreateDate"]).days
                        kid = k["AccessKeyId"]
                        masked_kid = f"{kid[:8]}...{kid[-4:]}"
                        node_id = f"nhi:aws:key:{masked_kid}"
                        self.graph.add_node(
                            Node(
                                id=node_id,
                                name=f"IAM_Key:{uname} ({masked_kid})",
                                node_type="NHI",
                                subtype="AWS_Access_Key",
                                evidence=u_arn,
                                privilege_level=user_priv,
                                credential_type="long-lived",
                                rotation_age_days=age_days,
                                owner=uname,
                                metadata={"access_key_masked": masked_kid, "age_days": age_days},
                            )
                        )
        except Exception as exc:
            print(f"[!] AWS IAM read-only collection warning: {exc}", file=sys.stderr)

    def _collect_entra_id(self) -> None:
        token = os.environ.get("AZURE_ACCESS_TOKEN")
        if not token or requests is None:
            print("[!] AZURE_ACCESS_TOKEN env var or requests library missing; skipping live Entra ID scan.", file=sys.stderr)
            return

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            resp = requests.get("https://graph.microsoft.com/v1.0/applications", headers=headers, timeout=10)
            if resp.status_code == 200:
                now = datetime.datetime.now(datetime.timezone.utc)
                for app in resp.json().get("value", []):
                    app_id = app.get("appId")
                    display_name = app.get("displayName", "UnnamedApp")
                    creds = app.get("passwordCredentials", [])
                    max_age = 0
                    for c in creds:
                        start_str = c.get("startDateTime")
                        if start_str:
                            dt = datetime.datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                            max_age = max(max_age, (now - dt).days)

                    node_id = f"nhi:entra:app:{app_id}"
                    self.graph.add_node(
                        Node(
                            id=node_id,
                            name=f"EntraApp:{display_name}",
                            node_type="NHI",
                            subtype="Entra_Service_Principal",
                            evidence=f"entra://applications/{app_id}",
                            privilege_level="write",
                            credential_type="long-lived" if creds else "short-lived",
                            rotation_age_days=max_age,
                            metadata={"appId": app_id, "secret_count": len(creds)},
                        )
                    )
        except Exception as exc:
            print(f"[!] Entra ID read-only collection warning: {exc}", file=sys.stderr)

    def _collect_gcp_iam(self) -> None:
        adc_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if adc_path and Path(adc_path).exists():
            try:
                data = json.loads(Path(adc_path).read_text(encoding="utf-8"))
                client_email = data.get("client_email", "unknown-sa@gcp")
                key_id = data.get("private_key_id", "unknown")[:8]
                self.graph.add_node(
                    Node(
                        id=f"nhi:gcp:sa:{client_email}",
                        name=f"GCP_SA:{client_email}",
                        node_type="NHI",
                        subtype="GCP_Service_Account_Key",
                        evidence=f"ADC:{adc_path} (key_id:{key_id}...)",
                        privilege_level="admin",
                        credential_type="long-lived",
                        rotation_age_days=180,
                    )
                )
            except Exception:
                pass


# =====================================================================
# 4. Discovery Engine: Kubernetes Collector
# =====================================================================
class K8sCollector:
    """Scans Kubernetes ServiceAccounts, ClusterRoleBindings, Secrets, and Agent Deployments."""

    def __init__(self, graph: IdentityGraph) -> None:
        self.graph = graph

    def collect(self) -> None:
        if k8s_client is None or k8s_config is None:
            print("[!] kubernetes Python package not installed; skipping live cluster scan.", file=sys.stderr)
            return

        try:
            k8s_config.load_kube_config()
            v1 = k8s_client.CoreV1Api()
            rbac_v1 = k8s_client.RbacAuthorizationV1Api()

            crbs = rbac_v1.list_cluster_role_binding().items
            privileged_sas: Dict[str, str] = {}
            for crb in crbs:
                role_name = crb.role_ref.name
                if role_name in ("cluster-admin", "admin", "edit"):
                    for subj in crb.subjects or []:
                        if subj.kind == "ServiceAccount":
                            sa_key = f"{subj.namespace or 'default'}/{subj.name}"
                            privileged_sas[sa_key] = "wildcard" if role_name == "cluster-admin" else "admin"

            sas = v1.list_service_account_for_all_namespaces().items
            for sa in sas:
                ns = sa.metadata.namespace
                name = sa.metadata.name
                sa_key = f"{ns}/{name}"
                priv = privileged_sas.get(sa_key, "scoped")
                if priv != "scoped" or "agent" in name.lower() or "mcp" in name.lower():
                    self.graph.add_node(
                        Node(
                            id=f"nhi:k8s:sa:{sa_key}",
                            name=f"K8s_SA:{sa_key}",
                            node_type="NHI",
                            subtype="K8s_ServiceAccount",
                            evidence=f"k8s://{ns}/serviceaccounts/{name}",
                            privilege_level=priv,
                            credential_type="short-lived",
                            owner=(sa.metadata.annotations or {}).get("owner"),
                            metadata={"namespace": ns, "role_binding": priv},
                        )
                    )
        except Exception as exc:
            print(f"[!] Kubernetes read-only collection warning: {exc}", file=sys.stderr)


# =====================================================================
# 5. Discovery Engine: CI/CD Workflow Collector
# =====================================================================
class CICDCollector:
    """Parses GitHub Actions and GitLab CI YAML workflows for write-all permissions, long-lived tokens, and @owner tags."""

    def __init__(self, repo_path: str, provider: str, graph: IdentityGraph) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.provider = provider.lower()
        self.graph = graph

    def collect(self) -> None:
        if not self.repo_path.exists():
            return

        workflow_files: List[Path] = []
        if self.provider in ("github", "all"):
            gh_dir = self.repo_path / ".github" / "workflows"
            if gh_dir.exists():
                workflow_files.extend(list(gh_dir.glob("*.yml")) + list(gh_dir.glob("*.yaml")))
        if self.provider in ("gitlab", "all"):
            gl_file = self.repo_path / ".gitlab-ci.yml"
            if gl_file.exists():
                workflow_files.append(gl_file)

        for wf in workflow_files:
            rel_path = wf.relative_to(self.repo_path).as_posix()
            try:
                raw_text = wf.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            has_write_all = bool(re.search(r"permissions\s*:\s*write-all", raw_text, re.I))
            has_id_token_write = bool(re.search(r"id-token\s*:\s*write", raw_text, re.I))
            secret_refs = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", raw_text)
            owner_match = re.search(r"#\s*@owner:\s*([^\n\r]+)", raw_text, re.IGNORECASE)
            owner = owner_match.group(1).strip() if owner_match else None

            priv = "wildcard" if has_write_all else ("write" if has_id_token_write else "scoped")
            cred_type = "long-lived" if secret_refs else "short-lived"

            wf_id = f"nhi:cicd:{rel_path}"
            self.graph.add_node(
                Node(
                    id=wf_id,
                    name=f"Workflow_NHI ({wf.name})",
                    node_type="NHI",
                    subtype="CI_CD_Workflow_Identity",
                    evidence=f"{rel_path}",
                    privilege_level=priv,
                    credential_type=cred_type,
                    rotation_age_days=180 if secret_refs else 1,
                    owner=owner,
                    metadata={"secrets_referenced": list(set(secret_refs)), "write_all": has_write_all},
                )
            )


# =====================================================================
# Deterministic Risk Tiering & OWASP NHI Mapping Engine
# =====================================================================
class RiskTieringEngine:
    """
    Evaluates every Node in the IdentityGraph against the deterministic rule table.
    Includes split R3 rules:
      - RULE_T1_WILDCARD_EXPOSED: Wildcard privilege + >=1 aggravator
      - RULE_T1_ADMIN_MULTI_AGGRAVATOR: Admin privilege + >=2 aggravators
    """

    def __init__(self, graph: IdentityGraph, rules_config: Optional[Dict[str, Any]] = None) -> None:
        self.graph = graph
        self.config = rules_config or load_rules_config()

    def _rule_meta(self, rule_id: str) -> Dict[str, Any]:
        return self.config["rules"].get(rule_id, DEFAULT_RULES_CONFIG["rules"][rule_id])

    def _is_enabled(self, rule_id: str) -> bool:
        return bool(self._rule_meta(rule_id).get("enabled", True))

    @staticmethod
    def _collect_aggravators(node: Node) -> List[str]:
        aggravators: List[str] = []
        if node.autonomy_level == "fully_autonomous":
            aggravators.append("autonomy=fully_autonomous")
        if node.network_exposure == "public":
            aggravators.append("exposure=public")
        if node.credential_type == "long-lived":
            aggravators.append("credential=long-lived")
        if node.owner_status in ("missing", "departed", "inactive"):
            aggravators.append(f"owner_status={node.owner_status}")
        return aggravators

    def evaluate_all(self) -> None:
        self.graph.detect_orphaned_identities()
        reused_ids = self.graph.detect_secret_reuse()

        for node_id, node in self.graph.nodes.items():
            if node.node_type == "RESOURCE":
                continue
            self._score_node(node, is_reused=(node_id in reused_ids))

    def _score_node(self, node: Node, is_reused: bool) -> None:
        rot_threshold = int(self.config["thresholds"].get("rotation_max_age_days", 90))
        admin_min_agg = int(self.config["thresholds"].get("admin_min_aggravators", 2))
        aggravators = self._collect_aggravators(node)

        # Rule R1: Ghost Agent or Undocumented Runtime Process
        if self._is_enabled("RULE_T1_GHOST_AGENT") and node.is_ghost:
            meta = self._rule_meta("RULE_T1_GHOST_AGENT")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T1_GHOST_AGENT"
            node.matching_rule_desc = meta["description"]
            node.primary_risk_factor = meta["primary_risk_factor"]
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Unmonitored autonomous process ({node.evidence}) with {node.privilege_level} host access "
                f"and {node.network_exposure} network exposure."
            )
            node.remediation = (
                "Terminate unauthorized PID immediately, revoke its environment credentials, and enforce "
                "signed container/manifest deployment gates."
            )
            return

        # Rule R2: Hardcoded / Leaked Secret in Code or Config
        if self._is_enabled("RULE_T1_HARDCODED_SECRET") and (
            node.node_type == "SECRET" or node.credential_type == "hardcoded"
        ):
            meta = self._rule_meta("RULE_T1_HARDCODED_SECRET")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T1_HARDCODED_SECRET"
            node.matching_rule_desc = meta["description"]
            node.primary_risk_factor = meta["primary_risk_factor"]
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Any actor with repository read access can extract {node.name} at {node.evidence} "
                f"and impersonate dependent agents or cloud workloads."
            )
            node.remediation = (
                "Revoke the exposed key immediately, purge git history, and migrate to workload identity "
                "federation (OIDC) or a dynamic secrets manager."
            )
            return

        # Rule R3a: Wildcard Privilege + At Least 1 Aggravator
        if self._is_enabled("RULE_T1_WILDCARD_EXPOSED") and node.privilege_level == "wildcard" and len(aggravators) >= 1:
            meta = self._rule_meta("RULE_T1_WILDCARD_EXPOSED")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T1_WILDCARD_EXPOSED"
            node.matching_rule_desc = (
                f"Identity holds 'wildcard' privileges with aggravator(s): {', '.join(aggravators)}."
            )
            node.primary_risk_factor = f"Wildcard Privilege + ({', '.join(aggravators)})"
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Full administrative takeover across target environment ({node.evidence}); "
                f"wildcard permissions allow unrestricted lateral movement."
            )
            node.remediation = (
                "Replace cluster-admin/AdministratorAccess/write-all with a least-privilege policy scoped "
                "strictly to required resources and actions."
            )
            return

        # Rule R3b: Admin Privilege + Multi-Aggravator (>= 2 Aggravators)
        if (
            self._is_enabled("RULE_T1_ADMIN_MULTI_AGGRAVATOR")
            and node.privilege_level == "admin"
            and len(aggravators) >= admin_min_agg
        ):
            meta = self._rule_meta("RULE_T1_ADMIN_MULTI_AGGRAVATOR")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T1_ADMIN_MULTI_AGGRAVATOR"
            node.matching_rule_desc = (
                f"Identity holds 'admin' privileges with {len(aggravators)} aggravators: {', '.join(aggravators)}."
            )
            node.primary_risk_factor = f"Admin Privilege + {len(aggravators)} Aggravators ({', '.join(aggravators)})"
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"High-impact administrative compromise across target environment ({node.evidence}); "
                f"prompt injection or key theft yields privileged command execution."
            )
            node.remediation = (
                "Scope down admin permissions to least-privilege, assign an active owner, rotate credentials, "
                "and require human-in-the-loop approval for destructive tool calls."
            )
            return

        # Rule R4: Orphaned Identity (Missing or Departed Owner)
        if self._is_enabled("RULE_T2_ORPHANED_IDENTITY") and node.owner_status in ("missing", "departed", "inactive"):
            meta = self._rule_meta("RULE_T2_ORPHANED_IDENTITY")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T2_ORPHANED_IDENTITY"
            node.matching_rule_desc = (
                f"Owner metadata is '{node.owner_status}' (owner='{node.owner}'), leaving identity ungoverned."
            )
            node.primary_risk_factor = f"Orphaned Identity (Owner {node.owner_status})"
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Unmonitored identity ({node.name}) retains '{node.privilege_level}' access without accountability."
            )
            node.remediation = (
                "Assign an active human owner and team tag in IAM/K8s metadata, or decommission the NHI if unused."
            )
            return

        # Rule R5: Unrotated Long-Lived Credential (> threshold days)
        if (
            self._is_enabled("RULE_T2_UNROTATED_LONG_LIVED_KEY")
            and node.credential_type == "long-lived"
            and node.rotation_age_days > rot_threshold
        ):
            meta = self._rule_meta("RULE_T2_UNROTATED_LONG_LIVED_KEY")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T2_UNROTATED_LONG_LIVED_KEY"
            node.matching_rule_desc = (
                f"Long-lived credential has not been rotated for {node.rotation_age_days} days "
                f"(threshold: {rot_threshold} days)."
            )
            node.primary_risk_factor = f"Long-Lived Credential ({node.rotation_age_days}d old)"
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Extended window of compromise for {node.name} ({node.evidence}) across connected cloud/CI resources."
            )
            node.remediation = (
                "Enforce automated 30/60-day key rotation or replace static keys with short-lived OIDC tokens."
            )
            return

        # Rule R6: Shared/Reused NHI or Secret Across Multiple Agents/Workloads
        if self._is_enabled("RULE_T2_NHI_REUSE") and is_reused:
            meta = self._rule_meta("RULE_T2_NHI_REUSE")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T2_NHI_REUSE"
            node.matching_rule_desc = meta["description"]
            node.primary_risk_factor = meta["primary_risk_factor"]
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Compromise of any single consumer of {node.name} compromises all sibling workloads sharing this identity."
            )
            node.remediation = (
                "Provision dedicated, per-agent service accounts with isolated permissions and distinct credentials."
            )
            return

        # Rule R7: Write/Admin-capable Agent/MCP or Long-Lived Key
        if self._is_enabled("RULE_T3_ELEVATED_OR_STATIC_AUTH") and (
            node.privilege_level in ("write", "admin", "wildcard") or node.credential_type == "long-lived"
        ):
            meta = self._rule_meta("RULE_T3_ELEVATED_OR_STATIC_AUTH")
            node.risk_tier = meta["tier"]
            node.matching_rule_id = "RULE_T3_ELEVATED_OR_STATIC_AUTH"
            node.matching_rule_desc = (
                f"Identity has '{node.privilege_level}' permissions or uses static authentication ('{node.credential_type}')."
            )
            node.primary_risk_factor = f"Elevated Privilege / Static Auth ({node.privilege_level})"
            node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
            node.blast_radius = (
                f"Can modify state or invoke external tools within scoped boundary ({node.evidence})."
            )
            node.remediation = (
                "Audit tool permissions quarterly and restrict outbound network egress to allowlisted model endpoints."
            )
            return

        # Rule R8: Scoped, Short-Lived, Actively Owned Identity
        meta = self._rule_meta("RULE_T4_SCOPED_BASELINE")
        node.risk_tier = meta["tier"]
        node.matching_rule_id = "RULE_T4_SCOPED_BASELINE"
        node.matching_rule_desc = meta["description"]
        node.primary_risk_factor = meta["primary_risk_factor"]
        node.owasp_mapping = OWASP_NHI_2025.get(meta["owasp"], meta["owasp"])
        node.blast_radius = f"Minimal blast radius; restricted to read/scoped operations at {node.evidence}."
        node.remediation = "Maintain continuous posture monitoring and periodic access reviews."


# =====================================================================
# Synthetic Demo Inventory Generator
# =====================================================================
def load_synthetic_demo_inventory(graph: IdentityGraph) -> None:
    """
    Populates a realistic 9-identity multi-surface inventory.
    Produces deterministically: Tier 1 = 4, Tier 2 = 3, Tier 3 = 1, Tier 4 = 1.
    """
    demo_nodes = [
        Node(
            id="agent:src/agents/finops_crew.py:CrewAI:42",
            name="FinOps_Autonomous_Crew",
            node_type="AGENT",
            subtype="CrewAI",
            evidence="src/agents/finops_crew.py:42",
            privilege_level="admin",
            credential_type="hardcoded",
            rotation_age_days=210,
            owner="alice@example.com",
            owner_status="active",
            network_exposure="internal",
            autonomy_level="fully_autonomous",
            metadata={"model_endpoints": ["https://api.openai.com/v1"], "tools": ["aws_cost_explorer", "bash", "sql_db"]},
        ),
        Node(
            id="secret:sk-pro...[sha256:9f86d08188]",
            name="OpenAI_API_Key (sk-pro...[sha256:9f86d08188])",
            node_type="SECRET",
            subtype="OpenAI_API_Key",
            evidence="src/agents/finops_crew.py:14",
            privilege_level="write",
            credential_type="hardcoded",
            rotation_age_days=210,
            owner="alice@example.com",
            owner_status="active",
        ),
        Node(
            id="runtime:pid:31415",
            name="Runtime_AutoGen (PID 31415)",
            node_type="AGENT",
            subtype="AutoGen",
            evidence="PID:31415 cmd='python3 -m autogenstudio.ui --host 0.0.0.0 --port 8081'",
            privilege_level="admin",
            credential_type="long-lived",
            rotation_age_days=120,
            owner=None,
            owner_status="missing",
            network_exposure="public",
            autonomy_level="fully_autonomous",
            is_ghost=True,
            metadata={"pid": 31415, "listening": "0.0.0.0:8081"},
        ),
        Node(
            id="nhi:aws:role:BedrockAgentExecutionRole-Prod",
            name="BedrockAgentExecutionRole-Prod",
            node_type="NHI",
            subtype="AWS_IAM_Role",
            evidence="arn:aws:iam::123456789012:role/BedrockAgentExecutionRole-Prod",
            privilege_level="wildcard",
            credential_type="short-lived",
            rotation_age_days=0,
            owner="platform-team@example.com",
            owner_status="active",
            network_exposure="public",
            metadata={"attached_policy": "AdministratorAccess", "wildcard_trust": True},
        ),
        Node(
            id="mcp:claude_desktop_config.json:postgres-prod",
            name="MCP_Server:postgres-prod",
            node_type="MCP_SERVER",
            subtype="ModelContextProtocol",
            evidence="configs/claude_desktop_config.json:18",
            privilege_level="admin",
            credential_type="short-lived",
            rotation_age_days=15,
            owner="bob@example.com [departed]",
            owner_status="departed",
            network_exposure="internal",
            autonomy_level="tool_calling",
            metadata={"command": "npx", "args": "-y @modelcontextprotocol/server-postgres postgresql://prod-db:5432/main"},
        ),
        Node(
            id="nhi:entra:app:88a1b2c3-d4e5-4f6a-8b9c-0d1e2f3a4b5c",
            name="EntraApp:Copilot-Plugin-ServicePrincipal",
            node_type="NHI",
            subtype="Entra_Service_Principal",
            evidence="entra://applications/88a1b2c3-d4e5-4f6a-8b9c-0d1e2f3a4b5c",
            privilege_level="write",
            credential_type="long-lived",
            rotation_age_days=412,
            owner="secops@example.com",
            owner_status="active",
            network_exposure="internal",
        ),
        Node(
            id="nhi:k8s:sa:ai-agents/langchain-worker-sa",
            name="K8s_SA:ai-agents/langchain-worker-sa",
            node_type="NHI",
            subtype="K8s_ServiceAccount",
            evidence="k8s://ai-agents/serviceaccounts/langchain-worker-sa",
            privilege_level="admin",
            credential_type="short-lived",
            rotation_age_days=0,
            owner=None,
            owner_status="missing",
            network_exposure="internal",
            metadata={"cluster_role_binding": "admin"},
        ),
        Node(
            id="nhi:cicd:.github/workflows/agent-deploy.yml",
            name="Workflow_NHI (agent-deploy.yml)",
            node_type="NHI",
            subtype="CI_CD_Workflow_Identity",
            evidence=".github/workflows/agent-deploy.yml:6",
            privilege_level="admin",
            credential_type="long-lived",
            rotation_age_days=45,
            owner="devops@example.com",
            owner_status="active",
            network_exposure="internal",
            metadata={"permissions": "id-token: write", "secrets": ["AWS_PROD_SECRET_KEY"]},
        ),
        Node(
            id="agent:src/agents/support_triage.py:PydanticAI:19",
            name="Support_Triage_Classifier",
            node_type="AGENT",
            subtype="PydanticAI",
            evidence="src/agents/support_triage.py:19",
            privilege_level="scoped",
            credential_type="short-lived",
            rotation_age_days=7,
            owner="support-eng@example.com",
            owner_status="active",
            network_exposure="internal",
            autonomy_level="interactive",
            metadata={"model_endpoints": ["https://api.anthropic.com/v1"], "tools": ["read_ticket"]},
        ),
    ]

    for n in demo_nodes:
        graph.add_node(n)

    graph.add_edge("agent:src/agents/finops_crew.py:CrewAI:42", "secret:sk-pro...[sha256:9f86d08188]", "has_secret")
    graph.add_edge("agent:src/agents/finops_crew.py:CrewAI:42", "nhi:aws:role:BedrockAgentExecutionRole-Prod", "can_assume")
    graph.add_edge("runtime:pid:31415", "secret:sk-pro...[sha256:9f86d08188]", "has_secret")
    graph.add_edge("agent:src/agents/finops_crew.py:CrewAI:42", "mcp:claude_desktop_config.json:postgres-prod", "can_write")


# =====================================================================
# Report Writer (Markdown + JSON + SARIF 2.1.0 + Mermaid/DOT Graph)
# =====================================================================
class ReportWriter:
    """Generates deterministic Markdown, JSON, SARIF 2.1.0, and Mermaid/DOT Graph reports."""

    TIER_EMOJI = {
        "Tier 1": "🚨",
        "Tier 2": "⚠️",
        "Tier 3": "🔶",
        "Tier 4": "✅",
    }

    def __init__(self, graph: IdentityGraph, output_prefix: str) -> None:
        self.graph = graph
        self.output_prefix = output_prefix

    def write_reports(
        self,
        emit_sarif: bool = False,
        rules_config: Optional[Dict[str, Any]] = None,
        graph_format: Optional[str] = None,
    ) -> Tuple[str, str, Optional[str], Optional[str]]:
        nodes = [n for n in self.graph.nodes.values() if n.node_type != "RESOURCE"]
        nodes.sort(key=lambda x: (x.risk_tier, x.id))

        total_agents = sum(1 for n in nodes if n.node_type == "AGENT")
        total_nhis = sum(1 for n in nodes if n.node_type in ("NHI", "SECRET", "MCP_SERVER"))
        ghost_count = sum(1 for n in nodes if n.is_ghost)
        tier1_count = sum(1 for n in nodes if n.risk_tier == "Tier 1")

        summary = {
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine_version": "0.3",
            "total_identities_evaluated": len(nodes),
            "total_agents": total_agents,
            "total_nhis_secrets_mcp": total_nhis,
            "ghost_agent_count": ghost_count,
            "tier_1_critical_count": tier1_count,
            "tier_breakdown": {
                "Tier 1": tier1_count,
                "Tier 2": sum(1 for n in nodes if n.risk_tier == "Tier 2"),
                "Tier 3": sum(1 for n in nodes if n.risk_tier == "Tier 3"),
                "Tier 4": sum(1 for n in nodes if n.risk_tier == "Tier 4"),
            },
        }

        md_path = f"{self.output_prefix}.md"
        json_path = f"{self.output_prefix}.json"
        sarif_path: Optional[str] = None
        graph_path: Optional[str] = None
        graph_diagram_text: Optional[str] = None

        if graph_format and write_graph_export is not None:
            graph_path, graph_diagram_text = write_graph_export(self.graph, graph_format, self.output_prefix)

        Path(md_path).parent.mkdir(parents=True, exist_ok=True)
        md_content = self._render_markdown(summary, nodes, graph_format, graph_diagram_text)
        Path(md_path).write_text(md_content, encoding="utf-8")

        json_payload = {
            "executive_summary": summary,
            "identities": [asdict(n) for n in nodes],
            "trust_edges": [asdict(e) for e in self.graph.edges],
        }
        Path(json_path).write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

        if emit_sarif and write_sarif_report is not None:
            sarif_path = f"{self.output_prefix}.sarif"
            write_sarif_report(nodes, sarif_path, rules_config or DEFAULT_RULES_CONFIG)

        return md_path, json_path, sarif_path, graph_path

    def _render_markdown(
        self,
        summary: Dict[str, Any],
        nodes: List[Node],
        graph_format: Optional[str] = None,
        graph_diagram_text: Optional[str] = None,
    ) -> str:
        lines = [
            "# 🛡️ AgentGuard Exposure & Non-Human Identity (NHI) Risk Report",
            f"**Generated (UTC):** `{summary['generated_at_utc']}` | **Engine:** Deterministic Rule Engine v0.3 (Zero-LLM Verdict Path)",
            "",
            "## 📊 Executive Summary",
            "| Status | Metric | Count |",
            "| :---: | :--- | :--- |",
            f"| 🤖 | **Total AI Agents Discovered** | {summary['total_agents']} |",
            f"| 🔑 | **Total NHIs, Secrets & MCP Servers** | {summary['total_nhis_secrets_mcp']} |",
            f"| 👻 | **Ghost Agents (Untracked Runtime Processes)** | {summary['ghost_agent_count']} |",
            f"| 🚨 | **Tier 1 (Critical) Findings** | {summary['tier_1_critical_count']} |",
            f"| ⚠️ | **Tier 2 (High) Findings** | {summary['tier_breakdown']['Tier 2']} |",
            f"| 🔶 | **Tier 3 (Medium) Findings** | {summary['tier_breakdown']['Tier 3']} |",
            f"| ✅ | **Tier 4 (Low) Findings** | {summary['tier_breakdown']['Tier 4']} |",
            "",
        ]

        if graph_format and graph_diagram_text:
            fence_lang = "mermaid" if graph_format.lower() == "mermaid" else "dot"
            lines.extend(
                [
                    f"## 🕸️ Identity & Blast-Radius Topology ({graph_format.upper()})",
                    f"```{fence_lang}",
                    graph_diagram_text,
                    "```",
                    "",
                ]
            )

        lines.extend(
            [
                "## 📋 Deterministic Risk Table",
                "| Identity | Type | Tier | Primary Risk Factor | OWASP NHI Top 10 Mapping |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )

        for n in nodes:
            ghost_badge = " [GHOST]" if n.is_ghost else ""
            t_emoji = self.TIER_EMOJI.get(n.risk_tier, "✅")
            lines.append(
                f"| `{n.name}`{ghost_badge} | {n.node_type} ({n.subtype}) | {t_emoji} **{n.risk_tier}** | "
                f"{n.primary_risk_factor} | {n.owasp_mapping} |"
            )

        lines.extend(["", "## 🔍 Per-Identity Audit & Remediation Details", ""])
        for n in nodes:
            t_emoji = self.TIER_EMOJI.get(n.risk_tier, "✅")
            lines.extend(
                [
                    f"### {t_emoji} [{n.risk_tier}] `{n.name}` (`{n.id}`)",
                    f"- **Identity Classification:** `{n.node_type}` / `{n.subtype}` (Ghost Status: `{n.is_ghost}`)",
                    f"- **Evidence Location:** `{n.evidence}`",
                    f"- **Owner & Lifecycle Status:** `{n.owner or 'Unassigned'}` (`{n.owner_status}`)",
                    f"- **Deterministic Rule Matched:** `{n.matching_rule_id}` — {n.matching_rule_desc}",
                    f"- **OWASP NHI Top 10 (2025):** `{n.owasp_mapping}`",
                    "",
                    f"> **💥 Blast Radius:** {n.blast_radius}",
                    ">",
                    f"> **🛠️ Remediation:** {n.remediation}",
                    "",
                ]
            )

        return "\n".join(lines)


# =====================================================================
# CLI Entry Point
# =====================================================================
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard v0.3: Deterministic Discovery & Risk Scanner for AI Agents and Non-Human Identities.",
    )
    parser.add_argument("--repo", type=str, default=None, help="Scan a local code repository for agent frameworks, MCP configs, and secrets")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp"], default=None, help="Collect IAM roles, service principals, and access keys (read-only)")
    parser.add_argument("--k8s", action="store_true", help="Scan current Kubernetes context for ServiceAccounts, Secrets, and workloads")
    parser.add_argument("--ci", choices=["github", "gitlab"], default=None, help="Scan CI/CD workflow YAML files for over-privileged tokens")
    parser.add_argument("--runtime", action="store_true", help="Inspect running processes for agent runtime signatures and flag GHOST agents")
    parser.add_argument("--probe-mcp", nargs="?", const="127.0.0.1:3000,127.0.0.1:3001,127.0.0.1:8000,127.0.0.1:8080,0.0.0.0:3000", default=None, help="Probe local/bound host:port endpoints for unauthenticated live MCP SSE servers")
    parser.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 report (<output>.sarif) alongside Markdown and JSON reports")
    parser.add_argument("--graph-export", choices=["mermaid", "dot"], default=None, help="Render the in-memory IdentityGraph into Markdown and a standalone .mmd or .dot file")
    parser.add_argument("--rules", type=str, default="rules.yaml", help="Path to rule-config YAML file (default: rules.yaml with safe built-in fallback)")
    parser.add_argument("--output", type=str, default="./agentguard-report", help="Output path prefix for Markdown, JSON, SARIF, and Graph reports (default: ./agentguard-report)")
    parser.add_argument("--dry-run", action="store_true", help="Print the deterministic scan plan without executing collectors")
    return parser


def print_dry_run_plan(args: argparse.Namespace) -> None:
    any_target = any([args.repo, args.cloud, args.k8s, args.ci, args.runtime, args.probe_mcp])
    print("=== AgentGuard v0.3 Deterministic Scan Plan (--dry-run) ===")
    print(f"  [Rule Configuration] Path: {args.rules} (Fallback to safe built-in defaults if absent)")
    if not any_target:
        print("  [Mode] No explicit target flags passed -> Will run with built-in Synthetic Multi-Surface Inventory.")
    if args.repo:
        print(f"  [Collector 1: Static Repo Scanner] Target path: {Path(args.repo).resolve()}")
    if args.runtime:
        print("  [Collector 2: Runtime Process Inspector] Target: Local OS Process Table (ps)")
    if args.cloud:
        print(f"  [Collector 3: Cloud IAM Read-Only Collector] Provider: {args.cloud.upper()}")
    if args.k8s:
        print("  [Collector 4: Kubernetes RBAC & SA Scanner] Target: Current Kubeconfig Context")
    if args.ci:
        print(f"  [Collector 5: CI/CD Workflow Scanner] Provider: {args.ci.upper()} (Path: {Path(args.repo or '.').resolve()})")
    if args.probe_mcp:
        print(f"  [Collector 6: Live MCP SSE Endpoint Probe] Targets: {args.probe_mcp}")
    artifacts = [f"{args.output}.md", f"{args.output}.json"]
    if args.sarif:
        artifacts.append(f"{args.output}.sarif")
    if args.graph_export:
        ext = "mmd" if args.graph_export == "mermaid" else "dot"
        artifacts.append(f"{args.output}.{ext}")
    print(f"  [Output Artifacts] Will write: {', '.join(artifacts)}")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.dry_run:
        print_dry_run_plan(args)
        return 0

    rules_cfg = load_rules_config(args.rules)
    graph = IdentityGraph()
    any_explicit_flag = any([args.repo, args.cloud, args.k8s, args.ci, args.runtime, args.probe_mcp])

    known_files: Set[str] = set()
    if args.repo:
        repo_col = RepoCollector(args.repo, graph)
        repo_col.collect()
        known_files = repo_col.discovered_agent_files

    if args.ci:
        ci_col = CICDCollector(args.repo or ".", args.ci, graph)
        ci_col.collect()

    if args.cloud:
        cloud_col = CloudCollector(args.cloud, graph)
        cloud_col.collect()

    if args.k8s:
        k8s_col = K8sCollector(graph)
        k8s_col.collect()

    if args.runtime:
        rt_col = RuntimeCollector(graph, known_files)
        rt_col.collect()

    if args.probe_mcp and MCPSSEProbe is not None:
        targets = [t.strip() for t in args.probe_mcp.split(",") if t.strip()]
        probe = MCPSSEProbe(graph, targets=targets)
        probe.collect()

    if not any_explicit_flag and len(graph.nodes) == 0:
        print("[*] No target flags specified; loading built-in synthetic multi-surface test inventory...")
        load_synthetic_demo_inventory(graph)

    engine = RiskTieringEngine(graph, rules_config=rules_cfg)
    engine.evaluate_all()

    writer = ReportWriter(graph, args.output)
    md_file, json_file, sarif_file, graph_file = writer.write_reports(
        emit_sarif=args.sarif,
        rules_config=rules_cfg,
        graph_format=args.graph_export,
    )

    t1 = sum(1 for n in graph.nodes.values() if n.node_type != "RESOURCE" and n.risk_tier == "Tier 1")

    print("\n\033[96m" + "=" * 60 + "\033[0m")
    print("\033[1m[+] AgentGuard v0.3 - Scan Complete\033[0m")
    print("\033[96m" + "=" * 60 + "\033[0m")
    print(f"  \033[92m[+]\033[0m Evaluated: \033[1m{len(graph.nodes)}\033[0m identities")
    if t1 > 0:
        print(f"  \033[91m[-] Tier 1 Critical Findings: {t1}\033[0m")
    else:
        print(f"  \033[92m[+] No Tier 1 Findings\033[0m")

    print("\n  \033[94m[*] Output Artifacts:\033[0m")
    print(f"    - Markdown : {md_file}")
    print(f"    - JSON     : {json_file}")
    if sarif_file:
        print(f"    - SARIF    : {sarif_file}")
    if graph_file:
        print(f"    - Graph    : {graph_file} ({args.graph_export})")
    print("\033[96m" + "=" * 60 + "\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
