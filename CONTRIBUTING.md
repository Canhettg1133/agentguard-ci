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

3. **Run Unit Tests:**
   ```bash
   npm test
   ```

4. **Build the Project:**
   ```bash
   npm run build
   ```

5. **Test CLI Locally:**
   ```bash
   node dist/cli.js scan src/
   ```

---

## 🛡️ Adding a New Security Rule

1. To add a new secret pattern, update `src/core/rules/secrets.ts`.
2. To add a new AI safety/prompt injection rule, update `src/core/rules/ai-safety.ts`.
3. Add corresponding test cases in `tests/secrets.test.ts` or `tests/ai-safety.test.ts`.
4. Ensure tests pass with `npm test`.

---

## 📋 Pull Request Guidelines

- Ensure your branch is up to date with `main`.
- Add test coverage for any new patterns or logic.
- Verify `npm test` and `npm run build` succeed before submitting.
- Follow the Pull Request template.
