import { Finding, ReviewComment } from '../core/types.js';

export class OfflineReviewer {
  /**
   * Generates inline PR review comments based on scan findings.
   */
  public static generateInlineComments(findings: Finding[]): ReviewComment[] {
    return findings.map((f) => {
      let body = `### 🛡️ ${f.title}\n\n`;
      body += `**Severity:** \`${f.severity.toUpperCase()}\`\n\n`;
      body += `${f.description}\n\n`;

      if (f.suggestedFix) {
        body += `**Recommended Remediation:**\n${f.suggestedFix}\n\n`;
      }

      body += `> _AgentGuard Rule \`${f.ruleId}\`_`;

      return {
        path: f.file,
        line: f.line,
        body,
        side: 'RIGHT',
      };
    });
  }
}
