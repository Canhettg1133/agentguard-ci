import { Finding, ScanResult, Severity } from '../types.js';
import { AGENTGUARD_VERSION } from '../version.js';

const DEFAULT_RULE_CWES: Record<string, { cweId: string; owaspCategory?: string }> = {
  'SEC-001': { cweId: 'CWE-798' },
  'SEC-002': { cweId: 'CWE-798' },
  'SEC-003': { cweId: 'CWE-798' },
  'SEC-004': { cweId: 'CWE-798' },
  'SEC-005': { cweId: 'CWE-798' },
  'SEC-006': { cweId: 'CWE-798' },
  'SEC-007': { cweId: 'CWE-798' },
  'SEC-008': { cweId: 'CWE-798' },
  'SEC-009': { cweId: 'CWE-798' },
  'SEC-010': { cweId: 'CWE-798' },
  'AIS-001': { cweId: 'CWE-94', owaspCategory: 'LLM01: Prompt Injection' },
  'AIS-002': { cweId: 'CWE-95', owaspCategory: 'LLM02: Sensitive Information Disclosure' },
  'AIS-003': { cweId: 'CWE-78', owaspCategory: 'LLM02: Sensitive Information Disclosure' },
  'AIS-004': { cweId: 'CWE-400', owaspCategory: 'LLM04: Model Denial of Service' },
  'AIS-005': { cweId: 'CWE-502', owaspCategory: 'LLM02: Sensitive Information Disclosure' },
  'AIS-006': { cweId: 'CWE-798', owaspCategory: 'LLM02: Sensitive Information Disclosure' },
  'AIS-007': { cweId: 'CWE-918', owaspCategory: 'LLM02: Sensitive Information Disclosure' },
  'MCP-001': { cweId: 'CWE-22', owaspCategory: 'MCP Security: Filesystem Isolation' },
  'MCP-002': { cweId: 'CWE-78', owaspCategory: 'MCP Security: Tool Execution' },
  'MCP-003': { cweId: 'CWE-798', owaspCategory: 'MCP Security: Credential Exposure' },
  'MCP-004': { cweId: 'CWE-918', owaspCategory: 'MCP Security: SSRF in Tools' },
  'MCP-005': { cweId: 'CWE-20', owaspCategory: 'MCP Security: Input Validation' },
};

export class SarifFormatter {
  private static severityToSarifLevel(
    sev: Severity
  ): 'error' | 'warning' | 'note' {
    switch (sev) {
      case 'critical':
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
      case 'info':
        return 'note';
    }
  }

  /**
   * Generates a fully compliant OASIS SARIF v2.1.0 JSON string.
   */
  public static format(result: ScanResult): string {
    // Unique rule definitions
    const ruleMap = new Map<
      string,
      {
        id: string;
        name: string;
        description: string;
        severity: Severity;
        cweId?: string;
        owaspCategory?: string;
        referenceUrl?: string;
        suggestedFix?: string;
      }
    >();

    for (const f of result.findings) {
      if (!ruleMap.has(f.ruleId)) {
        const fallback = DEFAULT_RULE_CWES[f.ruleId];
        ruleMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          description: f.description,
          severity: f.severity,
          cweId: f.cweId || fallback?.cweId,
          owaspCategory: f.owaspCategory || fallback?.owaspCategory,
          referenceUrl: f.referenceUrl,
          suggestedFix: f.suggestedFix,
        });
      }
    }

    const rules = Array.from(ruleMap.values()).map((r) => {
      const tags = ['security', 'ai-safety'];
      if (r.cweId) {
        tags.push(`external/cwe/${r.cweId.toLowerCase()}`);
      }
      if (r.owaspCategory) {
        tags.push(
          `external/owasp/${r.owaspCategory
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '-')
            .replace(/-+/g, '-')}`
        );
      }

      return {
        id: r.id,
        name: r.name,
        shortDescription: {
          text: r.name,
        },
        fullDescription: {
          text: r.description,
        },
        help: {
          text: `${r.description}${
            r.suggestedFix ? `\nSuggested Remediation: ${r.suggestedFix}` : ''
          }`,
          markdown: `### ${r.name}\n\n${r.description}\n\n${
            r.suggestedFix ? `**Remediation:**\n${r.suggestedFix}\n\n` : ''
          }${r.referenceUrl ? `[Reference Documentation](${r.referenceUrl})` : ''}`,
        },
        helpUri: r.referenceUrl || 'https://github.com/Canhettg1133/agentguard-ci',
        defaultConfiguration: {
          level: this.severityToSarifLevel(r.severity),
        },
        properties: {
          tags,
          precision: 'high',
          problem: {
            severity: r.severity,
          },
        },
      };
    });

    const sarifResults = result.findings.map((f) => ({
      ruleId: f.ruleId,
      level: this.severityToSarifLevel(f.severity),
      message: {
        text: `${f.title}: ${f.description}${
          f.suggestedFix ? ` (Suggested Fix: ${f.suggestedFix})` : ''
        }`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file.replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: Math.max(1, f.line),
              startColumn: Math.max(1, f.column || 1),
              snippet: f.snippet
                ? {
                    text: f.snippet,
                  }
                : undefined,
            },
          },
        },
      ],
    }));

    const sarifReport = {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'AgentGuard-CI',
              version: AGENTGUARD_VERSION,
              informationUri: 'https://github.com/Canhettg1133/agentguard-ci',
              rules,
            },
          },
          results: sarifResults,
        },
      ],
    };

    return JSON.stringify(sarifReport, null, 2);
  }
}
