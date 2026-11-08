#!/usr/bin/env python3
from __future__ import annotations
import socket, urllib.error, urllib.request
from typing import Any, Dict, List, Optional, Tuple

class MCPSSEProbe:
    DEFAULT_TARGETS = ["127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:8000", "127.0.0.1:8080", "0.0.0.0:3000"]
    def __init__(self, graph: Any, targets: Optional[List[str]] = None, timeout: float = 0.75) -> None:
        self.graph = graph; self.targets = targets or self.DEFAULT_TARGETS; self.timeout = timeout
    @staticmethod
    def _parse_host_port(target: str) -> Tuple[str, int]:
        if ":" in target: host, port_s = target.rsplit(":", 1); return host.strip(), int(port_s)
        return target.strip(), 3000
    def _is_port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1" if host == "0.0.0.0" else host, port), timeout=self.timeout): return True
        except OSError: return False
    def _probe_sse_endpoint(self, host: str, port: int) -> Optional[str]:
        connect_host = "127.0.0.1" if host == "0.0.0.0" else host
        for path in ("/sse", "/mcp", "/messages"):
            url = f"http://{connect_host}:{port}{path}"
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "text/event-stream, application/json"}), timeout=self.timeout) as resp:
                    ctype = resp.headers.get("Content-Type", ""); chunk = resp.read(256).decode("utf-8", errors="ignore")
                    if ("text/event-stream" in ctype or "event: endpoint" in chunk or "jsonrpc" in chunk.lower() or resp.status == 200): return f"http://{host}:{port}{path}"
            except urllib.error.HTTPError as he:
                if he.code in (401, 403): return None
            except Exception: continue
        return None
    def collect(self, simulated_endpoints: Optional[List[Dict[str, Any]]] = None) -> None:
        from agentguard import Node
        if simulated_endpoints is not None:
            for ep in simulated_endpoints:
                host = ep.get("host", "127.0.0.1"); port = ep.get("port", 3000); path = ep.get("path", "/sse")
                if not ep.get("unauthenticated", True): continue
                is_public = host == "0.0.0.0" or ep.get("public", False)
                self.graph.add_node(Node(id=f"mcp:sse:{host}:{port}", name=f"Live_MCP_SSE ({host}:{port}{path})", node_type="MCP_SERVER", subtype="MCP_SSE_Endpoint", evidence=f"http://{host}:{port}{path}", privilege_level="admin" if is_public else "write", credential_type="none", owner=None, owner_status="missing", network_exposure="public" if is_public else "local", autonomy_level="tool_calling", is_ghost=ep.get("is_ghost", True), metadata={"url": f"http://{host}:{port}{path}", "unauthenticated": True}))
            return
        for target in self.targets:
            host, port = self._parse_host_port(target)
            if not self._is_port_open(host, port): continue
            matched_url = self._probe_sse_endpoint(host, port)
            if matched_url:
                is_public = host == "0.0.0.0"
                self.graph.add_node(Node(id=f"mcp:sse:{host}:{port}", name=f"Live_MCP_SSE ({host}:{port})", node_type="MCP_SERVER", subtype="MCP_SSE_Endpoint", evidence=matched_url, privilege_level="admin" if is_public else "write", credential_type="none", owner=None, owner_status="missing", network_exposure="public" if is_public else "local", autonomy_level="tool_calling", is_ghost=True, metadata={"url": matched_url, "unauthenticated": True}))
