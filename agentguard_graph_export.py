#!/usr/bin/env python3
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Tuple

def _sanitize_id(raw_id: str) -> str: return "n_" + re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)
def _escape_label(text: str) -> str: return text.replace('"', "'").replace("[", "(").replace("]", ")")

def render_mermaid(graph: Any) -> str:
    lines = ["flowchart TD", "    %% Deterministic Risk Tier Styling", "    classDef tier1 fill:#ffebee,stroke:#d32f2f,stroke-width:2px,color:#b71c1c;", "    classDef tier2 fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100;", "    classDef tier3 fill:#fffde7,stroke:#fbc02d,stroke-width:1.5px,color:#f57f17;", "    classDef tier4 fill:#e8f5e9,stroke:#388e3c,stroke-width:1.5px,color:#1b5e20;", "    classDef ghost fill:#fce4ec,stroke:#c2185b,stroke-width:3px,stroke-dasharray: 5 5,color:#880e4f;"]
    tier_to_class = {"Tier 1": "tier1", "Tier 2": "tier2", "Tier 3": "tier3", "Tier 4": "tier4"}
    for node in sorted(graph.nodes.values(), key=lambda x: (x.risk_tier, x.id)):
        safe_id = _sanitize_id(node.id); ghost_prefix = "[GHOST] " if node.is_ghost else ""
        label = _escape_label(f"{ghost_prefix}{node.name}<br/>({node.node_type} | {node.risk_tier})")
        if node.node_type == "AGENT": shape = f'{safe_id}(["{label}"])'
        elif node.node_type == "SECRET": shape = f'{safe_id}{{"{label}"}}'
        elif node.node_type == "MCP_SERVER": shape = f'{safe_id}[["{label}"]]'
        else: shape = f'{safe_id}["{label}"]'
        lines.append(f"    {shape}:::{'ghost' if node.is_ghost else tier_to_class.get(node.risk_tier, 'tier4')}")
    for edge in graph.edges: lines.append(f'    {_sanitize_id(edge.source)} -->|"{_escape_label(edge.relation)}"| {_sanitize_id(edge.target)}')
    return "\n".join(lines)

def render_dot(graph: Any) -> str:
    lines = ["digraph AgentGuardIdentityGraph {", '    rankdir="LR";', '    node [fontname="Helvetica", fontsize=10, style="filled,rounded"];', '    edge [fontname="Helvetica", fontsize=9];']
    tier_colors = {"Tier 1": ("#ffebee", "#d32f2f"), "Tier 2": ("#fff3e0", "#f57c00"), "Tier 3": ("#fffde7", "#fbc02d"), "Tier 4": ("#e8f5e9", "#388e3c")}
    type_shapes = {"AGENT": "octagon", "SECRET": "diamond", "MCP_SERVER": "component", "NHI": "box", "RESOURCE": "cylinder"}
    for node in sorted(graph.nodes.values(), key=lambda x: (x.risk_tier, x.id)):
        fill, stroke = tier_colors.get(node.risk_tier, ("#e8f5e9", "#388e3c")); shape = type_shapes.get(node.node_type, "box")
        lines.append(f'    {_sanitize_id(node.id)} [label="{_escape_label(("[GHOST] " if node.is_ghost else "") + node.name + chr(92) + "n[" + node.node_type + " | " + node.risk_tier + "]")}", shape="{shape}", fillcolor="{fill}", color="{stroke}", style="{"filled,dashed,bold" if node.is_ghost else "filled,rounded"}"];')
    for edge in graph.edges: lines.append(f'    {_sanitize_id(edge.source)} -> {_sanitize_id(edge.target)} [label="{_escape_label(edge.relation)}"];')
    return "\n".join(lines) + "\n}"

def write_graph_export(graph: Any, fmt: str, output_prefix: str) -> Tuple[str, str]:
    fmt_lower = fmt.lower().strip()
    if fmt_lower == "mermaid": content = render_mermaid(graph); out_path = f"{output_prefix}.mmd"
    elif fmt_lower == "dot": content = render_dot(graph); out_path = f"{output_prefix}.dot"
    else: raise ValueError(f"Unsupported graph format: {fmt}")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True); Path(out_path).write_text(content, encoding="utf-8"); return out_path, content
