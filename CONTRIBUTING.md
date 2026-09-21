# Contributing to AgentGuard-CI

Thank you for your interest in contributing to **AgentGuard-CI**! We welcome all contributions, including new security rules, bug fixes, documentation improvements, and feedback.

---

## 🛠️ Development Setup

1. **Fork and Clone the Repository:**
   ```bash
   git clone https://github.com/Canhettg1133/agentguard-ci.git
   cd agentguard-ci
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Run Unit Tests & Typecheck:**
   ```bash
   npm test
   npm run typecheck
   ```

4. **Build the Project:**
   ```bash
   npm run build
   ```

5. **Run Benchmark Suite:**
   ```bash
   node dist/cli.js benchmark
   ```

---

## Adding a New Security Rule

1. To add a new secret pattern, update `src/core/rules/secrets.ts`.
2. To add a new AI safety or prompt injection rule, update `src/core/rules/ai-safety.ts`.
3. To add a new Model Context Protocol (MCP) guardrail, update `src/core/rules/mcp-safety.ts`.
4. Add corresponding unit tests in `tests/secrets.test.ts`, `tests/ai-safety.test.ts`, or `tests/mcp-safety.test.ts`.
5. Add representative regression vectors to `src/benchmark/fixtures.ts`.
6. Ensure 100% test passing (`npm test`) and zero type errors (`npm run typecheck`).

---

## Pull Request Guidelines

- Ensure your branch is up to date with `main`.
- Maintain strict typing (`tsc --noEmit` must pass with 0 errors).
- Add test coverage for any new patterns or logic.
- Ensure 100% passing tests (`npm test`) and verified benchmark regression (`node dist/cli.js benchmark`).
- Avoid unnecessary dependencies and keep bundle overhead minimal.
