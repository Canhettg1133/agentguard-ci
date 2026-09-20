import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/core/scanner.js';

describe('Scanner Core Engine', () => {
  it('scans content and identifies both secret leaks and AI safety issues', () => {
    const code = `
      const openaiKey = "sk-proj-12345678901234567890123456789012";
      eval(aiOutput);
    `;

    const scanner = new Scanner();
    const findings = scanner.scanContent(code, 'src/app.ts');

    expect(findings.length).toBe(2);
    const result = scanner.generateResult(findings, 1, 10, 'high');
    expect(result.passed).toBe(false);
    expect(result.summary.critical).toBe(1);
    expect(result.summary.high).toBe(1);
    expect(result.riskScore).toBeGreaterThan(50);
  });

  it('scans unified git diff and correctly attributes added lines', () => {
    const diff = `diff --git a/src/config.ts b/src/config.ts
index 83db48f..bf269f4 100644
--- a/src/config.ts
+++ b/src/config.ts
@@ -10,3 +10,4 @@ export const appConfig = {
   port: 3000,
+  apiKey: "sk-proj-abcdef1234567890abcdef1234567890",
 };
`;

    const scanner = new Scanner();
    const findings = scanner.scanDiff(diff);

    expect(findings.length).toBe(1);
    expect(findings[0].file).toBe('src/config.ts');
    expect(findings[0].line).toBe(11);
    expect(findings[0].severity).toBe('critical');
  });

  it('passes cleanly on clean code', () => {
    const cleanCode = `
      export function add(a: number, b: number): number {
        return a + b;
      }
    `;

    const scanner = new Scanner();
    const findings = scanner.scanContent(cleanCode, 'src/math.ts');
    const result = scanner.generateResult(findings, 1, 5, 'high');

    expect(findings.length).toBe(0);
    expect(result.passed).toBe(true);
    expect(result.riskScore).toBe(0);
  });

  it('scans multiline git diffs and detects prompt injection across lines', () => {
    const multilineDiff = `diff --git a/src/agent.ts b/src/agent.ts
index 1111111..2222222 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -20,4 +20,8 @@ export function createAgent() {
   const model = 'gpt-4o';
+  const message = {
+    role: 'system',
+    content: \`You are an assistant. \${req.body.userPrompt}\`
+  };
   return message;
 }
`;

    const scanner = new Scanner();
    const findings = scanner.scanDiff(multilineDiff);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings.find((f) => f.ruleId === 'AIS-001');
    expect(finding).toBeDefined();
    expect(finding?.file).toBe('src/agent.ts');
    expect(finding?.severity).toBe('high');
  });

  it('scans multiline MCP configuration in git diff and detects root directory exposure', () => {
    const mcpDiff = `diff --git a/mcp_config.yaml b/mcp_config.yaml
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/mcp_config.yaml
@@ -0,0 +1,5 @@
+mcpServers:
+  filesystem:
+    command: npx
+    allowedDirectories:
+      - "/"
`;

    const scanner = new Scanner();
    const findings = scanner.scanDiff(mcpDiff);

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('MCP-001');
    expect(findings[0].file).toBe('mcp_config.yaml');
    expect(findings[0].severity).toBe('critical');
  });

  it('ignores pre-existing context lines in git diff and only flags newly added lines', () => {
    const contextOnlyDiff = `diff --git a/src/config.ts b/src/config.ts
index 83db48f..bf269f4 100644
--- a/src/config.ts
+++ b/src/config.ts
@@ -10,4 +10,5 @@
   // Pre-existing context line containing dummy or old code:
   const oldCode = 123;
+  const safeAddition = "hello world";
   return safeAddition;
`;

    const scanner = new Scanner();
    const findings = scanner.scanDiff(contextOnlyDiff);

    expect(findings.length).toBe(0);
  });
});
