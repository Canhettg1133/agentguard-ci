import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/core/scanner.js';

describe('Inline Suppression Mechanism', () => {
  it('suppresses finding using agentguard-disable-next-line', () => {
    const code = `
      // agentguard-disable-next-line AIS-002
      eval(aiOutput);
    `;

    const scanner = new Scanner();
    const findings = scanner.scanContent(code, 'src/test.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].suppressed).toBe(true);

    const result = scanner.generateResult(findings, 1, 5, 'high');
    expect(result.passed).toBe(true);
    expect(result.riskScore).toBe(0);
    expect(result.suppressedCount).toBe(1);
  });

  it('suppresses finding using inline agentguard-ignore', () => {
    const code = `
      eval(aiOutput); // agentguard-ignore: AIS-002
    `;

    const scanner = new Scanner();
    const findings = scanner.scanContent(code, 'src/test.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].suppressed).toBe(true);

    const result = scanner.generateResult(findings, 1, 5, 'high');
    expect(result.passed).toBe(true);
  });

  it('suppresses multiple lines using block comments', () => {
    const code = `
      /* agentguard-disable */
      eval(aiOutput);
      const k = "sk-proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ";
      /* agentguard-enable */
    `;

    const scanner = new Scanner();
    const findings = scanner.scanContent(code, 'src/test.ts');
    for (const f of findings) {
      expect(f.suppressed).toBe(true);
    }

    const result = scanner.generateResult(findings, 1, 5, 'high');
    expect(result.passed).toBe(true);
    expect(result.findings.length).toBe(0);
  });
});
