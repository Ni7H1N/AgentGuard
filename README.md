 <div align="center">

  <br />

  <h1>🛡️ AgentGuard</h1>

  <p><strong>The Nmap for AI Agents, MCP Servers & Non-Human Identities</strong></p>

  <p>
    Zero-inventory discovery, in-memory blast-radius graph analysis, and deterministic risk tiering mapped to the OWASP Non-Human Identities Top 10 (2025).
  </p>

  <br />

  <p>
    <a href="https://github.com/Ni7H1N">
      <img src="https://img.shields.io/badge/Maintainer-%40Ni7H1N-00f2fe?style=for-the-badge&logo=github&logoColor=white" alt="Maintainer" />
    </a>
    <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/Python-3.10%2B-38bdf8?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
    </a>
    <a href="https://owasp.org/www-project-non-human-identities-top-10/">
      <img src="https://img.shields.io/badge/OWASP-NHI_Top_10_2025-ef4444?style=for-the-badge&logo=owasp&logoColor=white" alt="OWASP NHI Top 10" />
    </a>
    <a href="https://github.com/Ni7H1N/AgentGuard">
      <img src="https://img.shields.io/badge/Output-SARIF_2.1.0_%7C_Mermaid-10b981?style=for-the-badge" alt="SARIF and Mermaid" />
    </a>
    <a href="LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="MIT License" />
    </a>
  </p>

  <br />

</div>

---

## 🚀 What is AgentGuard?

**AgentGuard** is an open-source, single-command security posture and discovery scanner built for the modern AI engineering stack.

Modern applications deploy dozens of autonomous AI agents, Model Context Protocol (MCP) servers, cloud IAM roles, and CI/CD service identities — often with zero visibility or inventory.

AgentGuard bridges this gap using a **100% deterministic, zero-LLM verdict engine** that runs locally in milliseconds.

It discovers hidden identities, maps their relationships, identifies excessive privileges, and highlights potential security risks across your AI infrastructure.

---

## ✨ Key Capabilities

- **🤖 Static Code & Config Discovery (`--repo`):** Recursively scans Python codebases, `.env` files, and configuration manifests for LangChain, CrewAI, AutoGen, PydanticAI, OpenAI/Anthropic SDKs, and MCP servers. Extracts tool definitions, autonomy flags, cross-file secret reuse, and SHA-256 secret fingerprints. Raw secrets are never stored.

- **👻 Ghost Agent Runtime Detection (`--runtime`):** Cross-references live OS processes (`ps`) and network sockets against discovered source files, supporting absolute, relative, module, and basename path matching to identify untracked AI runtimes.

- **🔌 Live MCP SSE Endpoint Probe (`--probe-mcp`):** Probes configured host/port pairs for unauthenticated Model Context Protocol `/sse`, `/mcp`, and `/messages` endpoints.

- **☁️ Cloud IAM Collectors (`--cloud aws|azure|gcp`):** Read-only inspection of AWS IAM roles and access keys, Microsoft Entra ID service principals, and GCP service account metadata. Includes automatic AWS user/group policy privilege resolution.

- **☸️ Kubernetes Collector (`--k8s`):** Enumerates `ServiceAccounts` and `ClusterRoleBindings` to identify over-privileged cluster-admin or wildcard bindings on agent workloads.

- **🔄 CI/CD Workflow Scanner (`--ci github|gitlab`):** Parses GitHub Actions and GitLab CI YAML workflows to detect `permissions: write-all`, unpinned OIDC `id-token: write` grants, and long-lived CI secrets.

- **⚙️ Configurable Deterministic Rule Engine (`--rules rules.yaml`):** Evaluates discovered identities against customizable rules such as `RULE_T1_GHOST_AGENT`, `RULE_T1_HARDCODED_SECRET`, `RULE_T1_WILDCARD_EXPOSED`, and `RULE_T1_ADMIN_MULTI_AGGRAVATOR`.

- **📊 Multi-Format Output (`--sarif`, `--graph-export mermaid|dot`):** Generates Markdown reports, JSON feeds, SARIF 2.1.0 reports for GitHub Security code scanning, and Mermaid/Graphviz DOT blast-radius diagrams.

---

## 🛠️ Installation

**Requirements:** Python 3.10+

### 1. Clone the repository

```bash
git clone https://github.com/Ni7H1N/AgentGuard.git
cd AgentGuard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Verify installation

```bash
python3 agentguard.py --help
```

---

## 📖 Usage Examples

### 1. Default Scan

Run AgentGuard without target flags to load its built-in synthetic multi-surface demo inventory.

```bash
python3 agentguard.py
```

### 2. Full Multi-Surface Security Audit

Scan a repository, AWS IAM, Kubernetes, GitHub Actions, runtime processes, and MCP endpoints while exporting SARIF and Mermaid graph reports.

```bash
python3 agentguard.py \
  --repo ./my-agent-app \
  --cloud aws \
  --k8s \
  --ci github \
  --runtime \
  --probe-mcp \
  --sarif \
  --graph-export mermaid \
  --output ./reports/prod-audit
```

### 3. Dry-Run Scan Plan

Preview the planned scan without executing the collectors.

```bash
python3 agentguard.py \
  --repo . \
  --cloud aws \
  --k8s \
  --runtime \
  --dry-run
```

### 4. Export SARIF Results

Generate a SARIF 2.1.0 report for security analysis and compatible GitHub code scanning workflows.

```bash
python3 agentguard.py --repo . --sarif
```

### 5. Export Blast-Radius Graph

Generate a Mermaid topology diagram.

```bash
python3 agentguard.py --repo . --graph-export mermaid
```

---

## 🛡️ Deterministic Risk Tiers & OWASP Mapping

AgentGuard assigns every discovered identity to one of four deterministic risk tiers mapped to the OWASP Non-Human Identities Top 10 (2025).

| Risk Tier | Risk Level | Primary Trigger Conditions | OWASP NHI Mapping |
|:---:|---|---|:---:|
| 🚨 Tier 1 | **Critical** | Ghost agents, hardcoded plaintext secrets, exposed wildcard privileges, admin privileges with multiple aggravators | NHI1, NHI2, NHI5 |
| ⚠️ Tier 2 | **High** | Orphaned identities, unrotated long-lived keys (over 90 days), cross-workload secret reuse | NHI1, NHI7, NHI9 |
| 🔶 Tier 3 | **Medium** | Elevated write/admin permissions or static authentication below Tier 1 thresholds | NHI4 |
| ✅ Tier 4 | **Low** | Scoped privileges, short-lived tokens, internal exposure, and verified active ownership | NHI6 |

**Key principle:** Risk classification is deterministic and rule-based. No LLM inference is required to produce security verdicts.

---

## 🧪 Running the Test Suite

AgentGuard includes a pytest suite covering collectors, graph algorithms, rule tiers, SARIF generation, and MCP probing.

Run the tests:

```bash
pytest -v
```

---

## 📦 Project Structure

```text
AgentGuard/
│
├── agentguard.py              # Main CLI entry point & discovery orchestration
├── agentguard_sarif.py        # SARIF 2.1.0 formatter
├── agentguard_graph_export.py # Mermaid & Graphviz DOT topology renderer
├── mcp_sse_probe.py           # MCP SSE & JSON-RPC probe
├── rules.yaml                 # Customizable risk rules & thresholds
├── requirements.txt           # Python dependencies
│
├── tests/
│   ├── __init__.py
│   ├── test_tiering.py        # Rule and risk-tier tests
│   └── test_graph_export.py   # Graph export tests
│
└── .github/
    └── workflows/
        └── agentguard.yml     # CI pipeline and SARIF upload
```

---

## 🔐 Security Philosophy

AgentGuard is built around three principles:

1. **Visibility:** Discover identities and AI runtimes that traditional security inventory tools may overlook.
2. **Determinism:** Produce consistent, explainable security verdicts using a local rule-based engine.
3. **Actionability:** Map identity relationships and security findings into structured reports and blast-radius graphs.

---

<div align="center">

  **Built for the security of the autonomous AI era.**

  🛡️ **AgentGuard** | Discover. Analyze. Secure.

  <br />

  <a href="https://github.com/Ni7H1N/AgentGuard">
    <img src="https://img.shields.io/badge/Explore-AgentGuard-00f2fe?style=for-the-badge&logo=github&logoColor=white" alt="Explore AgentGuard" />
  </a>

</div>
