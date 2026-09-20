import { Finding, ReviewComment } from '../core/types.js';

export class OfflineReviewer {
  /**
   * Generates formatted inline PR review comments based on scan findings for offline CI runs.
   */
  public static generateInlineComments(findings: Finding[]): ReviewComment[] {
    return findings
      .filter((f) => !f.suppressed)
      .map((f) => ({
        path: f.file.replace(/\\/g, '/'),
        line: Math.max(1, f.line),
        body: this.buildCommentBody(f),
        side: 'RIGHT',
      }));
  }

  /**
   * Builds an offline comment body for a single finding with remediation advice.
   */
  public static buildCommentBody(f: Finding): string {
    let body = `### 🛡️ AgentGuard-CI: \`[${f.ruleId}]\` ${f.title}\n\n`;
    body += `**Severity:** \`${f.severity.toUpperCase()}\` | **Category:** \`${f.category}\`\n\n`;
    body += `${f.description}\n\n`;

    if (f.suggestedFix) {
      body += `**Recommended Remediation:** ${f.suggestedFix}\n`;
    }

    body += `\n> _Automated guardrail via AgentGuard-CI (Rule \`${f.ruleId}\`)_`;
    return body;
  }
}

