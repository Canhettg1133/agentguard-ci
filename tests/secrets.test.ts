import { describe, it, expect } from 'vitest';
import { secretRules } from '../src/core/rules/secrets.js';

describe('Secrets Scanner Rule Engine', () => {
  it('detects live OpenAI API key', () => {
    const code = 'const apiKey = "sk-proj-abc1234567890abcdef1234567890abcdef";';
    const rule = secretRules.find((r) => r.id === 'SEC-001')!;
    const findings = rule.match(code, 'src/api.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].ruleId).toBe('SEC-001');
    expect(findings[0].snippet).toContain('sk-p...cdef');
  });

  it('detects Anthropic Claude API key', () => {
    const code = 'const anthropicKey = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890";';
    const rule = secretRules.find((r) => r.id === 'SEC-002')!;
    const findings = rule.match(code, 'src/client.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('detects AWS Access Key ID', () => {
    const code = 'const awsKey = "AKIA1234567890ABCDEF";';
    const rule = secretRules.find((r) => r.id === 'SEC-005')!;
    const findings = rule.match(code, 'config/aws.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('high');
  });

  it('detects database connection string with embedded password', () => {
    const code = 'const db = "postgres://admin:SuperSecretPass123!@db.internal:5432/mydb";';
    const rule = secretRules.find((r) => r.id === 'SEC-007')!;
    const findings = rule.match(code, 'src/db.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('detects live Groq API key (SEC-011)', () => {
    const code = 'const groq = "gsk_9aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLm";';
    const rule = secretRules.find((r) => r.id === 'SEC-011')!;
    const findings = rule.match(code, 'src/groq.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].ruleId).toBe('SEC-011');
  });

  it('detects live LangSmith / LangChain API key (SEC-012)', () => {
    const code = 'const langKey = "lsv2_pt_9aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678_0aBcDe";';
    const rule = secretRules.find((r) => r.id === 'SEC-012')!;
    const findings = rule.match(code, 'src/langchain.ts');

    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].ruleId).toBe('SEC-012');
  });

  it('ignores harmless environment variable references and placeholders', () => {
    const safeCode = `
      const key1 = process.env.OPENAI_API_KEY;
      const key2 = "sk-proj-YOUR_API_KEY_HERE";
      const key3 = "sk-ant-example-placeholder";
      const key4 = "gsk_your_groq_api_key_placeholder";
      const key5 = "lsv2_pt_your_mock_key_here";
    `;
    for (const rule of secretRules) {
      const findings = rule.match(safeCode, 'src/safe.ts');
      expect(findings.length).toBe(0);
    }
  });
});
