# AgentGuard-CI

AI-native security guardrail, Model Context Protocol (MCP) validator, and OpenAI Codex code reviewer for GitHub Actions and local CLI.

[![CI Test Suite](https://github.com/Canhettg1133/agentguard-ci/actions/workflows/ci.yml/badge.svg)](https://github.com/Canhettg1133/agentguard-ci/actions)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-v2.1.0_OASIS-purple?style=flat-square&logo=github)](https://docs.github.com/en/code-security/code-scanning)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP%20LLM%20Top%2010-Compliant-darkgreen?style=flat-square)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![npm version](https://img.shields.io/npm/v/agentguard-ci.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/agentguard-ci)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-blue.svg?style=flat-square)](package.json)

---

## Overview

Modern software development increasingly incorporates LLMs, AI agents, and Model Context Protocol (MCP) servers. With this shift, repositories face security challenges specific to AI engineering:

1. **Credential Exposure:** Hardcoded API keys (`sk-proj-...`, `sk-ant-...`, Cloud tokens) committed to git diffs.
2. **Prompt Injection Vectors:** Direct user input interpolation into system instructions (CWE-94 / OWASP LLM01).
3. **Unsafe Dynamic Execution:** Arbitrary code execution (`eval()`, `new Function()`) on unsanitized model completions.
4. **Model Context Protocol (MCP) Misconfigurations:** Tool execution schemas exposing host root filesystems (`allowedDirectories: ["/"]` or `["C:\\"]`) or executing unsanitized shell commands.
5. **False Positive Fatigue:** Heuristic alerts triggered on test mocks and harmless variable names.

**AgentGuard-CI** operates as a dual-engine security guardrail. It functions locally in the terminal and as a native GitHub Action on Pull Requests, generating OASIS SARIF v2.1.0 reports for GitHub Code Scanning and optional 1-click suggested code patches via OpenAI Codex.

---

## Architecture: Dual-Engine Design

AgentGuard-CI splits deterministic scanning from semantic evaluation:

```
                  ┌─────────────────────────────────────────┐
                  │    Git Diff / Local Source Files        │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                 Engine 1: Offline Scanner                   │
        │  • Shannon Entropy Check (H ≥ 3.2 bits)                     │
        │  • AST & Regex Rules (AI Safety, Prompt Injection)          │
        │  • MCP Configuration Validator (Allowed Dirs, Tool Schemas) │
        │  • Inline Suppression Parser (agentguard-disable-next-line) │
        │  Execution latency: < 1 ms | Network calls: 0               │
        └──────────────┬──────────────────────────────┬───────────────┘
                       │                              │
                       ▼                              ▼
        ┌──────────────────────────────┐ ┌──────────────────────────────┐
        │  Terminal / Markdown / SARIF │ │ Engine 2: Codex Reviewer     │
        │  • ANSI CLI output           │ │ (Requires OPENAI_API_KEY)    │
        │  • OASIS SARIF v2.1.0        │ │ • Strict JSON Schema output  │
        │  • Step Summaries            │ │ • False-positive filtering   │
        └──────────────────────────────┘ │ • 1-click suggested diffs    │
                                         └──────────────┬───────────────┘
                                                        │
                                                        ▼
                                         ┌──────────────────────────────┐
                                         │ GitHub PR Inline Review      │
                                         │ ```suggestion code patches   │
                                         └──────────────────────────────┘
```

1. **Deterministic Heuristic Engine (Offline):**
   - Scans files and git diffs in sub-milliseconds without network dependencies or API keys.
   - Evaluates Shannon Entropy ($H(X) = -\sum P(x) \log_2 P(x)$) on candidate credentials to discard low-entropy dummy strings (`sk-proj-test-1234567890`).
   - Analyzes unified git diff hunks with real line tracking so pre-existing code untouched by the PR does not trigger alerts.

2. **OpenAI Codex Semantic Verification Layer (Optional):**
   - Activated when `OPENAI_API_KEY` is present.
   - Sends diff context to OpenAI models with strict Structured Outputs (`response_format: { type: "json_schema", ... }`).
   - Classifies findings as `CONFIRMED_VULNERABILITY`, `FALSE_POSITIVE`, or `NEEDS_INVESTIGATION`.
   - Synthesizes formatted GitHub diff replacements (````suggestion````) directly applicable on PR review lines.

---

## Quickstart

### Running via NPX

No global installation required:

```bash
# Scan full repository
npx agentguard-ci scan

# Scan only staged git changes (recommended for pre-commit)
npx agentguard-ci diff --staged

# Review PR branch diff with OpenAI Codex semantic verification locally
npx agentguard-ci review main

# Run AI review on staged pre-commit changes
npx agentguard-ci review --staged

# Scan branch differences against main
npx agentguard-ci diff main --ai

# Scan last 5 git commits for leaked credentials
npx agentguard-ci diff --history 5

# Export OASIS SARIF v2.1.0 for GitHub Code Scanning
npx agentguard-ci scan ./src --format sarif --output report.sarif

# Run 4-tier regression accuracy benchmark suite
npx agentguard-ci benchmark
```

---

## Output Examples

### 1. Terminal Output (`agentguard-ci diff --staged`)

```text
AgentGuard-CI - Security & Code Quality Guardrail
────────────────────────────────────────────────────────────

Found 2 security finding(s):

File: src/agent/planner.ts
  [ HIGH ] AIS-001: Prompt Injection Risk (Line 42)
    User-controlled input directly concatenated into LLM system prompt.
    Snippet: const prompt = `You are a helpful assistant. ${req.body.userInput}`;
    Remediation: Separate system instructions from user role messages in messages array.

File: src/config/credentials.ts
  [ CRITICAL ] SEC-001: OpenAI API Key Leak (Line 14)
    Exposed active OpenAI Secret Key with high Shannon Entropy.
    Snippet: const apiKey = "sk-proj-9xK1mQ8zLp...[REDACTED_SECRET]";
    Entropy: 4.82 bits
    Remediation: Move secret credential to process.env.OPENAI_API_KEY.

────────────────────────────────────────────────────────────
Risk Score: 78/100 | Scanned in 18ms
Summary: 1 Critical | 1 High | 0 Medium | 0 Low | 0 Info
CHECK FAILED: Critical or High severity issues detected.
```

### 2. GitHub Pull Request Review (Codex Suggested Patch)

When running in GitHub Actions with `OPENAI_API_KEY`, AgentGuard-CI submits targeted inline reviews:

> #### AgentGuard-CI: `[AIS-001]` Prompt Injection Risk
> **Severity:** `HIGH` | **Category:** `ai-safety`
>
> User input is interpolated directly into system instructions, allowing prompt hijacking (CWE-94 / OWASP LLM01).
>
> > **OpenAI Codex Assessment:** The diff interpolates an untrusted request parameter into the system prompt template. Refactoring into a discrete `user` message safely isolates untrusted input.
>
> **Suggested remediation:**
> ```suggestion
>     const messages = [
>       { role: 'system', content: 'You are a helpful assistant.' },
>       { role: 'user', content: req.body.userInput }
>     ];
> ```
> _Automated guardrail via AgentGuard-CI (Rule `AIS-001`)_

---

## GitHub Actions & SARIF Integration

Create `.github/workflows/agentguard.yml` or run `npx agentguard-ci init`:

```yaml
name: AgentGuard Security & Code Scanning

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  agentguard:
    name: Security & PR Guardrail
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run AgentGuard-CI
        uses: Canhettg1133/agentguard-ci@v0.2.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-severity: 'high'
          comment-on-pr: 'true'
          sarif-file: 'agentguard-report.sarif'
          # openai-api-key: ${{ secrets.OPENAI_API_KEY }} # Optional

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'agentguard-report.sarif'
```

---

## Local Pre-Commit Integration

### Option A: Built-in Git Hook
Install a pre-commit hook with zero external dependencies:

```bash
npx agentguard-ci hook install
```

To remove:
```bash
npx agentguard-ci hook uninstall
```

### Option B: `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/Canhettg1133/agentguard-ci
    rev: v0.2.0
    hooks:
      - id: agentguard
```

### Option C: Husky
```bash
npx husky add .husky/pre-commit "npx agentguard-ci diff --staged --threshold high"
```

---

## Security Rules

### Model Context Protocol (MCP) Rules (`MCP-xxx`)

| Rule ID | Rule Name | Scope | Severity |
| :--- | :--- | :--- | :---: |
| `MCP-001` | Unrestricted Filesystem Exposure | Roots mapped to `/` or `C:\` in MCP config | `CRITICAL` |
| `MCP-002` | Shell Command Injection in Tool Definition | `shell: true` with unsanitized argument interpolation | `HIGH` |
| `MCP-003` | Hardcoded Credentials in MCP Env Config | Plaintext keys in `claude_desktop_config.json` or `mcp.json` | `CRITICAL` |
| `MCP-004` | Unconstrained SSRF in MCP Tool Execution | Dynamic URL fetches lacking loopback/metadata defenses | `HIGH` |
| `MCP-005` | Missing or Empty Tool Input Schema | Empty `inputSchema` allowing arbitrary payloads | `MEDIUM` |

### Secret Leak Rules with Shannon Entropy (`SEC-xxx`)

All secret rules evaluate Shannon Entropy ($H \ge 3.2$) to ignore dummy placeholders:

| Rule ID | Target Credential | Format / Pattern | Severity |
| :--- | :--- | :--- | :---: |
| `SEC-001` | OpenAI API Key | `sk-...`, `sk-proj-...`, `sk-admin-...` | `CRITICAL` |
| `SEC-002` | Anthropic Claude API Key | `sk-ant-...` | `CRITICAL` |
| `SEC-003` | Google Cloud / Gemini API Key | `AIzaSy...` | `CRITICAL` |
| `SEC-004` | GitHub Personal Access Token | `ghp_...`, `github_pat_...` | `CRITICAL` |
| `SEC-005` | AWS Access Key ID | `AKIA...` | `HIGH` |
| `SEC-006` | Unencrypted Private Key | `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY` | `CRITICAL` |
| `SEC-007` | Database URI with Embedded Auth | `postgres://`, `mongodb://`, `mysql://` | `CRITICAL` |
| `SEC-008` | Hugging Face Token | `hf_...` | `HIGH` |
| `SEC-009` | Stripe Live Secret Key | `sk_live_...` | `CRITICAL` |
| `SEC-010` | Slack Bot / Webhook Token | `hooks.slack.com`, `xoxb-...` | `HIGH` |

### AI Safety & Prompt Injection Rules (`AIS-xxx`)

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `AIS-001` | Prompt Injection Risk | User-controlled input interpolated directly into system instructions | `HIGH` |
| `AIS-002` | Dynamic Model Execution | Dangerous `eval()`, `new Function()`, or `exec()` on LLM outputs | `HIGH` |
| `AIS-003` | Tool Command Injection | Shell string execution in AI agent tool handlers | `HIGH` |
| `AIS-004` | Unbounded Token Generation | Model API invocation without `max_tokens` or timeout guards | `MEDIUM` |
| `AIS-005` | Unsafe Deserialization | Arbitrary pickle/deserialization on agent memory caches | `HIGH` |
| `AIS-006` | Vector Database Credential Leak | Plaintext Pinecone, Qdrant, ChromaDB, or Weaviate API keys | `HIGH` |
| `AIS-007` | Unprotected SSRF in Agent Tool | Web-fetching agent tool without private IP/metadata validation | `HIGH` |

---

## 4-Tier Threat Regression Benchmark

AgentGuard-CI includes an internal evaluation suite verifying rule accuracy and false-positive resistance across 35 multi-language test vectors across 4 threat categories:

```bash
npx agentguard-ci benchmark
```

```text
⚡ AgentGuard-CI - Detection Accuracy & Regression Suite
══════════════════════════════════════════════════════════════
Dataset: 35 Multi-Language Test Cases (Secrets, AI Safety, MCP)
Standards: OWASP Top 10 for LLM (2025) · CWE-94 · CWE-78 · CWE-918 · CWE-798 · MCP Spec
──────────────────────────────────────────────────────────────
  ✔ True Positives (TP):  23   |  ✔ True Negatives (TN):  12
  ✖ False Positives (FP): 0   |  ✖ False Negatives (FN): 0
──────────────────────────────────────────────────────────────
  Precision (P):  100%  (Zero false alarms)
  Recall (R):     100%  (Detection rate)
  F1-Score:       100%  (Harmonic mean)
  Mean Latency:   0.26 ms per scan
──────────────────────────────────────────────────────────────
Threat Category Evaluation:
  ✔ Tier 1: Secrets & Shannon Entropy      TP: 9/9 · FN: 0
  ✔ Tier 2: OWASP Top 10 for LLM           TP: 8/8 · FN: 0
  ✔ Tier 3: Model Context Protocol (MCP)   TP: 6/6 · FN: 0
  ✔ Tier 4: False Positive Resistance      TN: 12/12 · FP: 0
══════════════════════════════════════════════════════════════
🌟 BENCHMARK PASSED: Enterprise-grade accuracy & sub-millisecond latency.
```

---

## Configuration

Customize behavior using `.agentguardrc.json` in repository root:

```json
{
  "ignorePaths": [
    "dist/**",
    "coverage/**",
    "vendor/**",
    "fixtures/**"
  ],
  "disabledRules": [
    "AIS-004"
  ],
  "severityOverrides": {
    "SEC-005": "critical"
  },
  "minEntropy": 3.2,
  "failThreshold": "high"
}
```

### Inline Suppressions

Suppress individual findings directly in code:

```typescript
// Suppress next line for a specific rule:
// agentguard-disable-next-line AIS-002
eval(untrustedAiCompletion);

// Inline suppression:
const token = "sk-proj-test-mock"; // agentguard-ignore: SEC-001

// Disable for an entire block:
/* agentguard-disable */
// Test mocks...
/* agentguard-enable */
```

---

## CLI Reference

```text
Usage: agentguard [options] [command]

Commands:
  scan [options] [target]            Scan a directory or file (default: .)
  diff [options] [commitOrBranch]    Scan git diffs (--staged, branch, or --history <n>, --ai)
  review [options] [commitOrBranch]  Perform AI semantic code review with OpenAI Codex on git changes
  hook <action>                      Manage local git pre-commit hook (install | uninstall)
  benchmark                          Run internal 4-tier accuracy benchmark suite
  init                               Generate GitHub Actions workflow (.github/workflows/agentguard.yml)

Options:
  -V, --version                      Display version number
  -h, --help                         Display help for command
```

---

## License

This project is licensed under the [MIT License](LICENSE).
Security vulnerability reporting: [SECURITY.md](SECURITY.md).
