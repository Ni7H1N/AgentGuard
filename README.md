<div align="center">

  <img src="banner.svg" alt="AgentGuard Architecture Banner" width="100%" />

  <br><br>

  <a href="https://github.com/Ni7H1N">
    <img src="https://img.shields.io/badge/MAINTAINER-%40Ni7H1N-00f2fe?style=for-the-badge&logo=github&logoColor=white" />
  </a>
  <img src="https://img.shields.io/badge/PYTHON-3.10%2B-38bdf8?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/OWASP-NHI_TOP_10-ef4444?style=for-the-badge&logo=owasp&logoColor=white" />
  <img src="https://img.shields.io/badge/OUTPUT-SARIF_2.1.0_%7C_MERMAID-10b981?style=for-the-badge" />

</div>

# 🛡️ AgentGuard

### AI-Powered Security Scanner for Non-Human Identities

AgentGuard is a security analysis tool designed to identify, investigate, and visualize security risks associated with Non-Human Identities (NHIs), including AI agents, service accounts, API tokens, and automated workloads.

It helps security teams discover identity-related weaknesses, analyze potential attack paths, and generate actionable security reports.

---

## ✨ Features

- 🔍 **Identity Discovery** – Identify and analyze Non-Human Identities.
- 🛡️ **Security Analysis** – Detect potential identity security weaknesses.
- 🤖 **AI Agent Security** – Analyze risks associated with autonomous agents.
- 📊 **Attack Path Visualization** – Visualize identity relationships and potential attack paths.
- 📄 **SARIF Support** – Generate standardized SARIF 2.1.0 security output.
- 🕸️ **Mermaid Diagrams** – Visualize identity relationships and security architecture.
- ⚡ **Automated Scanning** – Streamline security assessment workflows.
- 🔐 **NHI Security** – Align security analysis with the OWASP Non-Human Identities Top 10.

---

## 🏗️ Architecture

AgentGuard brings identity discovery, security analysis, and reporting together in a unified workflow.

```mermaid
flowchart TD
    A["Identity Sources"] --> B["AgentGuard Scanner"]
    B --> C["Identity Discovery"]
    C --> D["Security Analysis"]
    D --> E["Risk Assessment"]
    E --> F["Attack Path Analysis"]
    F --> G["Security Reports"]
    G --> H["SARIF 2.1.0"]
    G --> I["Mermaid Visualization"]

    style A fill:#172554,stroke:#38bdf8,color:#fff
    style B fill:#164e63,stroke:#22d3ee,color:#fff
    style E fill:#7f1d1d,stroke:#ef4444,color:#fff
    style G fill:#14532d,stroke:#22c55e,color:#fff
