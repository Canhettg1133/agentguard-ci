import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { loadConfig } from '../src/core/config.js';
import { Scanner } from '../src/core/scanner.js';

describe('Project Configuration (.agentguardrc.json)', () => {
  const testConfigPath = path.resolve(process.cwd(), '.agentguardrc.json');

  afterEach(() => {
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }
  });

  it('loads default config when no configuration file exists in clean directory', () => {
    const config = loadConfig(path.resolve(process.cwd(), 'node_modules'));
    expect(config.failThreshold).toBe('high');
    expect(config.minEntropy).toBe(3.0);
    expect(config.ignorePaths).toEqual(['dist/**', 'build/**', 'node_modules/**', 'coverage/**']);
    expect(config.disabledRules).toEqual([]);
  });

  it('automatically imports .gitignore patterns into ignorePaths', () => {
    const config = loadConfig();
    expect(config.ignorePaths).toContain('node_modules/');
    expect(config.ignorePaths).toContain('coverage/');
  });

  it('correctly parses .agentguardrc.json and applies custom settings', () => {
    const customConfig = {
      ignorePaths: ['generated/**', 'legacy/'],
      disabledRules: ['AIS-004'],
      severityOverrides: {
        'SEC-005': 'critical',
      },
      minEntropy: 3.5,
      failThreshold: 'critical',
    };

    fs.writeFileSync(testConfigPath, JSON.stringify(customConfig), 'utf-8');

    const loaded = loadConfig();
    expect(loaded.ignorePaths).toContain('legacy/');
    expect(loaded.disabledRules).toContain('AIS-004');
    expect(loaded.severityOverrides['SEC-005']).toBe('critical');
    expect(loaded.failThreshold).toBe('critical');

    // Verify scanner respects disabledRules and ignorePaths
    const scanner = new Scanner({ config: loaded });
    expect(scanner.isIgnored('legacy/old-file.ts')).toBe(true);
    expect(scanner.isIgnored('src/index.ts')).toBe(false);

    // Ignored path returns zero findings
    const ignoredFindings = scanner.scanContent(
      'const k = "sk-proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ";',
      'legacy/secrets.ts'
    );
    expect(ignoredFindings.length).toBe(0);
  });
});
