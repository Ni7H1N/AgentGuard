from agentguard import *
from agentguard_graph_export import render_mermaid

def test_mermaid():
    graph = IdentityGraph(); load_synthetic_demo_inventory(graph); RiskTieringEngine(graph).evaluate_all()
    assert "flowchart TD" in render_mermaid(graph)
