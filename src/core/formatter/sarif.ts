import { Finding, ScanResult, Severity } from '../types.js';

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
      }
    >();

    for (const f of result.findings) {
      if (!ruleMap.has(f.ruleId)) {
        ruleMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          description: f.description,
          severity: f.severity,
        });
      }
    }

    const rules = Array.from(ruleMap.values()).map((r) => ({
      id: r.id,
      name: r.name,
      shortDescription: {
        text: r.name,
      },
      fullDescription: {
        text: r.description,
      },
      defaultConfiguration: {
        level: this.severityToSarifLevel(r.severity),
      },
      properties: {
        problem: {
          severity: r.severity,
        },
      },
    }));

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
              version: '0.1.0',
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
