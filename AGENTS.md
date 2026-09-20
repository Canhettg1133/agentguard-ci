# AGENTS.md - Repository Architecture & Engineering Guidelines

This document outlines the architectural standards, design principles, and code quality expectations for contributors and automated agents working on **AgentGuard-CI**.

---

## 1. Core Engineering Principles

* **Think Before Coding:** Explicitly state assumptions. Never guess silently or introduce speculative abstractions.
* **Simplicity First:** Write the minimum code necessary to solve the problem. Avoid over-engineering, unused configuration flags, and unnecessary dependencies.
* **Surgical Changes:** Modify only the files and lines relevant to the feature or bugfix. Do not reformat unrelated code.
* **Goal-Driven Verification:** Every change must have verifiable success criteria and maintain 100% passing tests (`npm test`).
* **Zero Dead Code:** Every module, class, and utility function must be actively integrated and exercised. No orphaned abstractions or placeholder implementations.

---

## 2. Layered Clean Architecture & Deep Modules

The codebase strictly separates pure domain logic from side-effects and external I/O:

* `src/core/`: Pure domain logic, deterministic rules, and formatters with zero network or filesystem side-effects.
  * `src/core/rules/`: Plug-and-play security rules (Secrets with Shannon Entropy, AI Safety, and MCP security).
  * `src/core/formatter/`: Presentation formatters (Terminal ANSI, Markdown PR comment, OASIS SARIF v2.1.0).
  * `src/core/config.ts`: Project configuration and `.agentguardignore` resolution.
* `src/review/`: Review synthesis engine. Dual-Engine architecture combining offline rule-based remediation suggestions with an optional OpenAI Codex semantic verification layer.
* `src/cli/`: Node.js Command Line Interface adapter (Commander, file walker, exit codes).
* `src/action/`: GitHub Actions runner adapter (GitHub Octokit, annotations, Step Summaries, and PR review comments).

---

## 3. Strict Typing & Testing Standards

* **TypeScript Strict Mode:** 100% strict type coverage without `any` escapes.
* **Unit Testing:** All new rules, formatters, and config options must include unit tests in `tests/`.
* **Zero False Positives:** Test suites and mock fixtures must not trigger false alarms during workspace scans.

---

## 4. Autonomous Execution & Operational Boundaries

* **Autonomous End-to-End Execution:** The AI assistant must proactively execute all build, test, git commit, git push, git tag, and GitHub Release deployment tasks autonomously. Never delegate routine GitHub operations (creating tags, pushing branches, publishing GitHub releases via API) to the USER.
* **Single User Boundary (NPM Publishing):** The only manual step retained by the USER is `npm publish` (due to registry 2FA/credentials). All other tasks from code implementation to live GitHub release and CI monitoring must be completely handled and verified by the assistant.
* **Continuous Liveness & Remote CI Verification:** After every deployment, verify remote GitHub Actions workflow runs (`actions/runs`) to ensure 100% passing green builds.
