# 🛡️ AgentGuard v0.3

**AgentGuard** is an open-source, single-command deterministic security scanner for **AI Agents**, **Model Context Protocol (MCP) servers**, and **Non-Human Identities (NHIs)**.

It maps findings directly to the **OWASP Non-Human Identities Top 10 (2025)** and integrates seamlessly into CI/CD pipelines via SARIF.

## 🚀 Features
- **Static Code Analysis (`--repo`):** Finds LangChain, CrewAI, AutoGen, and PydanticAI agents. Extracts tools, autonomy levels, and SHA-256 fingerprints of hardcoded secrets.
- **MCP Discovery (`--probe-mcp`):** Probes for unauthenticated Model Context Protocol endpoints.
- **Ghost Agent Detection (`--runtime`):** Inspects the live OS process table for AI agents running without corresponding source code (Shadow AI).
- **Cloud IAM (`--cloud`):** Read-only AWS/Azure/GCP collectors for over-privileged roles.
- **Insecure CI/CD (`--ci`):** Detects `write-all` permissions and leaked secrets in GitHub/GitLab workflows.
- **Graph Export (`--graph-export`):** Generates Mermaid/DOT blast-radius topology graphs.
- **GitHub Security (`--sarif`):** Emits SARIF 2.1.0 for native GitHub Code Scanning.

## 📦 Installation
```bash
pip install -r requirements.txt
