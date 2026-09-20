import { Finding, ScanResult, Severity } from '../types.js';

export class MarkdownFormatter {
  private static severityEmoji(sev: Severity): string {
    switch (sev) {
      case 'critical':
        return '🔴 `CRITICAL`';
      case 'high':
        return '🟠 `HIGH`';
      case 'medium':
        return '🟡 `MEDIUM`';
      case 'low':
        return '🔵 `LOW`';
      case 'info':
        return '⚪ `INFO`';
    }
  }

  public static formatPRComment(result: ScanResult, aiInsights?: string): string {
    const lines: string[] = [];

    lines.push('## 🛡️ AgentGuard-CI Security & Code Quality Report');
    lines.push('<!-- agentguard-ci-report -->');
    lines.push('');

    const statusBadge = result.passed
      ? '![Passed](https://img.shields.io/badge/AgentGuard-PASSED-success?style=for-the-badge&logo=shield)'
      : '![Failed](https://img.shields.io/badge/AgentGuard-ACTION_REQUIRED-critical?style=for-the-badge&logo=shield)';

    lines.push(`${statusBadge} `);
    lines.push('');

    // Summary Table
    lines.push('### 📊 Executive Summary');
    lines.push('');
    lines.push('| Metric | Status |');
    lines.push('| :--- | :--- |');
    lines.push(
      `| **Risk Score** | \`${result.riskScore}/100\` (${
        result.riskScore > 50
          ? '🚨 High Risk'
          : result.riskScore > 20
          ? '⚠️ Moderate Risk'
          : '✅ Safe'
      }) |`
    );
    lines.push(`| **Files Scanned** | ${result.scannedFiles} |`);
    lines.push(
      `| **Findings Breakdown** | 🔴 ${result.summary.critical} Critical · 🟠 ${result.summary.high} High · 🟡 ${result.summary.medium} Medium · 🔵 ${result.summary.low} Low |`
    );
    lines.push(`| **Scan Duration** | ${result.durationMs}ms |`);
    lines.push('');

    if (aiInsights) {
      lines.push('### 🤖 AI Semantic Reviewer Notes');
      lines.push('');
      lines.push(aiInsights);
      lines.push('');
    }

    if (result.findings.length === 0) {
      lines.push('---');
      lines.push('🎉 **No security vulnerabilities or secret leaks detected in this PR!**');
      lines.push('');
      lines.push(
        '_Powered by [AgentGuard-CI](https://github.com/Canhettg1133/agentguard-ci) · Open Source Security Guardrail_'
      );
      return lines.join('\n');
    }

    lines.push('### 🔍 Detailed Findings');
    lines.push('');

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const f of result.findings) {
      if (!byFile.has(f.file)) {
        byFile.set(f.file, []);
      }
      byFile.get(f.file)!.push(f);
    }

    for (const [file, findings] of byFile.entries()) {
      lines.push(`<details open>`);
      lines.push(`<summary><b>📄 ${file} (${findings.length} issue${findings.length > 1 ? 's' : ''})</b></summary>`);
      lines.push('');
      lines.push('| Severity | Rule | Line | Description | Suggested Remediation |');
      lines.push('| :--- | :--- | :---: | :--- | :--- |');

      for (const f of findings) {
        const sev = this.severityEmoji(f.severity);
        const fix = f.suggestedFix ? f.suggestedFix.replace(/\|/g, '\\|') : 'None';
        const desc = f.description.replace(/\|/g, '\\|');
        lines.push(`| ${sev} | **${f.title}** | \`${f.line}\` | ${desc} | ${fix} |`);
      }

      lines.push('');
      lines.push('</details>');
      lines.push('');
    }

    lines.push('---');
    lines.push(
      '💡 *Maintainer Note: Critical or High severity findings should be resolved before merging to protect repository security.*'
    );
    lines.push('');
    lines.push(
      '_Protected by [AgentGuard-CI](https://github.com/Canhettg1133/agentguard-ci) — Automated Open Source PR Security_'
    );

    return lines.join('\n');
  }
}
