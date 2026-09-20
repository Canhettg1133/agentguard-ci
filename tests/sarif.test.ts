import { describe, it, expect } from 'vitest';
import { SarifFormatter } from '../src/core/formatter/sarif.js';
import { ScanResult } from '../src/core/types.js';

describe('SARIF v2.1.0 Formatter', () => {
  it('formats scan result into a valid OASIS SARIF v2.1.0 document', () => {
    const mockResult: ScanResult = {
      totalFiles: 1,
      scannedFiles: 1,
      findings: [
        {
          id: 'SEC-001-10',
          ruleId: 'SEC-001',
          title: 'OpenAI API Key Leak',
          description: 'Detected a live OpenAI API key committed into source code.',
          severity: 'critical',
          category: 'secret',
          file: 'src/config.ts',
          line: 10,
          column: 5,
          snippet: 'const apiKey = "sk-proj-...";',
          suggestedFix: 'Move key to environment variable',
        },
      ],
      riskScore: 40,
      summary: {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      passed: false,
      durationMs: 12,
    };

    const sarifJson = SarifFormatter.format(mockResult);
    const parsed = JSON.parse(sarifJson);

    expect(parsed.$schema).toContain('sarif-schema-2.1.0.json');
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeDefined();
    expect(parsed.runs.length).toBe(1);

    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe('AgentGuard-CI');
    expect(run.tool.driver.rules.length).toBe(1);
    expect(run.tool.driver.rules[0].id).toBe('SEC-001');

    expect(run.results.length).toBe(1);
    expect(run.results[0].ruleId).toBe('SEC-001');
    expect(run.results[0].level).toBe('error');
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
      'src/config.ts'
    );
    expect(run.results[0].locations[0].physicalLocation.region.startLine).toBe(10);
  });
});
