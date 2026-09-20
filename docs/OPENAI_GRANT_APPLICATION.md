# OpenAI Codex for Open Source Grant Application Dossier
**Program:** OpenAI Codex for Open Source ($1,200 / 6 Months ChatGPT Pro 20x Subscription)  
**Project:** AgentGuard-CI  
**Repository:** [https://github.com/Canhettg1133/agentguard-ci](https://github.com/Canhettg1133/agentguard-ci)  
**Primary Language:** TypeScript / Node.js (Active LTS 20+, 22+)  
**Distribution:** Dual-Engine (npm CLI `@agentguard-ci` & GitHub Actions Marketplace)

---

## 1. Project Information & Description

### What is the name and purpose of your open-source project?
**Project Name:** AgentGuard-CI  
**One-Line Pitch:** A zero-config, dual-engine AI security guardrail and automated PR reviewer that intercepts secret leaks, prompt injections, and Model Context Protocol (MCP) vulnerabilities while using OpenAI models for intelligent semantic code patch suggestions.

**Full Description:**
As open-source software rapidly adopts Large Language Models (LLMs) and the Model Context Protocol (MCP), maintainers face unprecedented security challenges: accidental API key leaks in commits, indirect prompt injections in system prompts, and insecure tool execution schemas.

AgentGuard-CI acts as an automated security co-pilot for open-source maintainers. It runs both as a terminal CLI for local pre-commit checks and as a GitHub Action on Pull Requests:
1. **Offline Static Layer:** Uses Shannon Entropy analysis ($H(X) \ge 3.2$) to detect genuine API secrets (OpenAI, Anthropic, AWS, database URIs), analyzes MCP configurations (`claude_desktop_config.json`, `mcp_config.json`) for root path traversal and shell injection risks, and produces OASIS SARIF v2.1.0 reports natively ingested by GitHub Advanced Security.
2. **OpenAI Semantic Intelligence Layer:** Ingests unified PR git diffs through OpenAI's strict JSON Schema Structured Outputs (`response_format: { type: "json_schema", ... }`) to filter false positives, reason about semantic context, and generate 1-click suggested diffs (`suggestion`) directly on pull request lines.

---

## 2. Alignment with OpenAI Codex & LLMs

### How does your project utilize OpenAI models or Codex?
AgentGuard-CI integrates OpenAI models directly into the CI/CD pull request lifecycle:
- **Semantic Differential Review:** Instead of naive line regexes, AgentGuard-CI reconstructs full hunk context from Git diffs and invokes OpenAI models using strict structured outputs to determine whether a suspicious pattern represents a genuine security vulnerability or an intentional test mock.
- **Automated Fix Synthesis (Codex Co-Pilot):** When vulnerabilities are detected (such as unsanitized user prompt interpolation or hardcoded credentials), OpenAI models synthesize safe, drop-in replacement code patches formatted as GitHub Markdown suggestions, allowing maintainers to accept fixes in a single click.
- **Model Context Protocol (MCP) Semantic Schema Auditing:** OpenAI models analyze complex JSON tool schemas to verify whether agent tool definitions enforce proper input sanitization and least-privilege constraints.

### Why do you need ChatGPT Pro 20x / Codex Grant ($1,200)?
1. **High-Volume Continuous Benchmark & Evaluation:** We continuously evaluate AgentGuard-CI across a rigorous multi-language benchmark suite (`tests/benchmark.test.ts` and `src/benchmark/fixtures.ts`) to benchmark precision and recall against evolving prompt injection techniques. The ChatGPT Pro 20x subscription provides the reasoning throughput and rate limits necessary to test and refine our guardrail prompts across thousands of simulated PR diffs.
2. **Developing Next-Generation AST-Aware Context Windows:** We are expanding AgentGuard-CI to support deep repository-level semantic graphs. The advanced reasoning capabilities of OpenAI models allow us to build multi-file context comprehension for large open-source repositories without hallucinating false security alerts.
3. **Serving the Open-Source Community at Scale:** As an open-source tool distributed freely on GitHub Marketplace and npm, high-tier access allows the core maintainers to actively research emerging zero-day LLM jailbreaks and rapidly ship updated rules to safeguard thousands of downstream open-source repositories.

---

## 3. Standards, Architecture & Impeccable Quality

### How does the project demonstrate enterprise-grade engineering?
- **Zero AI Slop:** Pure, strongly-typed TypeScript codebase adhering to Deep Modules philosophy (compact public API, rich implementation) and Karpathy Guidelines.
- **OASIS SARIF v2.1.0 Compliant:** Automatically exports standardized security reports directly viewable in GitHub's Code Scanning and Security tab.
- **OWASP Top 10 for LLM Applications (2025) Aligned:** Explicitly mitigates LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM05 (Improper Output Handling), LLM06 (Excessive Agency & Insecure Tool Design), and LLM07 (System Prompt Leakage).
- **OpenSSF Best Practices & Scorecard Ready:** Fully automated CI running across Node.js 20.x & 22.x LTS, passing 100% unit test coverage, automated supply-chain security scanning, strict branch protection, and formal security disclosure policies (`SECURITY.md`).

---

## 4. Maintainer Commitment & Roadmap

### What is your maintenance plan for the next 6-12 months?
1. **Q1-Q2:** Expand native support for MCP (Model Context Protocol) 2025 specifications, including streaming tool calls and resource permission boundaries.
2. **Q3:** Launch real-time GitHub PR interactive bot triggers (`@agentguard review`, `@agentguard fix`) powered by OpenAI reasoning models.
3. **Q4:** Publish an open-source quarterly threat report analyzing the most common security misconfigurations in AI-agent repositories.
