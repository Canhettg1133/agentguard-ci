import pc from 'picocolors';
import { Finding, ScanResult, Severity } from '../types.js';

export class TerminalFormatter {
  private static severityBadge(sev: Severity): string {
    switch (sev) {
      case 'critical':
        return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
      case 'high':
        return pc.bgRed(pc.black(' HIGH '));
      case 'medium':
        return pc.bgYellow(pc.black(' MEDIUM '));
      case 'low':
        return pc.bgCyan(pc.black(' LOW '));
      case 'info':
        return pc.bgBlue(pc.white(' INFO '));
    }
  }

  public static format(result: ScanResult): string {
    const lines: string[] = [];

    // Header Banner
    lines.push('');
    lines.push(
      pc.bold(
        pc.cyan('🛡️  AgentGuard-CI') +
          pc.gray(' - AI & Secret Security Guardrail')
      )
    );
    lines.push(pc.gray('─'.repeat(60)));

    if (result.findings.length === 0) {
      lines.push('');
      lines.push(
        pc.green(
          pc.bold('✨ All checks passed! No security or AI safety risks found.')
        )
      );
      lines.push(
        pc.gray(
          `Scanned ${result.scannedFiles} file(s) in ${result.durationMs}ms.`
        )
      );
      if (result.suppressedCount && result.suppressedCount > 0) {
        lines.push(
          pc.dim(`(${result.suppressedCount} issue(s) suppressed via inline comments)`)
        );
      }
      lines.push('');
      return lines.join('\n');
    }

    // Group findings by file
    const byFile = new Map<string, Finding[]>();
    for (const f of result.findings) {
      if (!byFile.has(f.file)) {
        byFile.set(f.file, []);
      }
      byFile.get(f.file)!.push(f);
    }

    lines.push('');
    lines.push(
      pc.bold(pc.red(`Found ${result.findings.length} security finding(s):`))
    );
    lines.push('');

    for (const [file, findings] of byFile.entries()) {
      lines.push(pc.bold(pc.underline(pc.white(`📄 ${file}`))));

      for (const f of findings) {
        const badge = this.severityBadge(f.severity);
        lines.push(
          `  ${badge} ${pc.bold(f.title)} ${pc.gray(`(Line ${f.line})`)}`
        );
        lines.push(`    ${pc.gray(f.description)}`);

        if (f.snippet) {
          lines.push(
            `    ${pc.dim('Code: ')} ${pc.italic(pc.yellow(f.snippet))}`
          );
        }

        if (f.entropy !== undefined) {
          lines.push(
            `    ${pc.dim('Shannon Entropy: ')} ${pc.magenta(
              `${f.entropy} bits`
            )}`
          );
        }

        if (f.suggestedFix) {
          lines.push(
            `    ${pc.green('💡 Fix: ')} ${pc.cyan(f.suggestedFix)}`
          );
        }
        lines.push('');
      }
    }

    // Risk Score & Summary Box
    lines.push(pc.gray('─'.repeat(60)));
    const riskColor =
      result.riskScore > 50
        ? pc.red
        : result.riskScore > 20
        ? pc.yellow
        : pc.green;

    lines.push(
      pc.bold('Risk Score: ') +
        riskColor(pc.bold(`${result.riskScore}/100`)) +
        pc.gray(` | Scanned in ${result.durationMs}ms`)
    );

    const s = result.summary;
    let summaryText = `Summary: ${pc.red(s.critical + ' Critical')} | ${pc.red(
      s.high + ' High'
    )} | ${pc.yellow(s.medium + ' Medium')} | ${pc.cyan(
      s.low + ' Low'
    )} | ${pc.blue(s.info + ' Info')}`;

    if (result.suppressedCount && result.suppressedCount > 0) {
      summaryText += ` | ${pc.dim(`${result.suppressedCount} Suppressed`)}`;
    }

    lines.push(summaryText);

    if (!result.passed) {
      lines.push('');
      lines.push(
        pc.bgRed(
          pc.white(
            pc.bold(' ❌ CHECK FAILED: Critical or High severity issues detected. ')
          )
        )
      );
    } else {
      lines.push('');
      lines.push(pc.green(pc.bold(' ✔ PASSED (Threshold met).')));
    }
    lines.push('');

    return lines.join('\n');
  }
}
