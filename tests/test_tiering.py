from agentguard import *
from mcp_sse_probe import MCPSSEProbe
import pytest, json
from pathlib import Path

def test_synthetic_inventory():
    graph = IdentityGraph(); load_synthetic_demo_inventory(graph); RiskTieringEngine(graph).evaluate_all()
    assert sum(1 for n in graph.nodes.values() if n.risk_tier == "Tier 1") == 4
