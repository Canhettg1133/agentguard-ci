import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/core/scanner.js';

describe('Python AI Safety Rules Verification', () => {
  const scanner = new Scanner();

  it('detects Python f-string prompt injection in system role', () => {
    const pythonCode = `
      import openai
      messages = [
          {"role": "system", "content": f"You are a helpful agent. Context: {user_query}"},
          {"role": "user", "content": "hello"}
      ]
    `;

    const findings = scanner.scanContent(pythonCode, 'agent/prompt.py');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('AIS-001');
    expect(findings[0].severity).toBe('high');
  });

  it('detects Python command injection in agent tool execution', () => {
    const pythonCode = `
      import subprocess
      def execute_tool(tool_args):
          subprocess.run(f"ls -la {tool_args.path}", shell=True)
    `;

    const findings = scanner.scanContent(pythonCode, 'tools/bash_tool.py');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('AIS-003');
    expect(findings[0].severity).toBe('high');
  });

  it('passes on safe parameterized Python code', () => {
    const pythonCode = `
      import subprocess
      def safe_tool(path):
          subprocess.run(["ls", "-la", path], shell=False)
    `;

    const findings = scanner.scanContent(pythonCode, 'tools/safe_tool.py');
    expect(findings.length).toBe(0);
  });
});
