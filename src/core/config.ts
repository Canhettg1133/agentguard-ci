import fs from 'node:fs';
import path from 'node:path';
import { Severity } from './types.js';

export interface AgentGuardConfig {
  ignorePaths?: string[];
  disabledRules?: string[];
  severityOverrides?: Record<string, Severity>;
  minEntropy?: number;
  failThreshold?: Severity;
}

export const DEFAULT_CONFIG: Required<AgentGuardConfig> = {
  ignorePaths: ['dist/**', 'build/**', 'node_modules/**', 'coverage/**'],
  disabledRules: [],
  severityOverrides: {},
  minEntropy: 3.0,
  failThreshold: 'high',
};

/**
 * Deep Module: Discovers and loads project-level configuration
 * from .agentguardrc.json or agentguard.config.json, automatically
 * honoring .gitignore entries.
 */
export function loadConfig(cwd: string = process.cwd()): Required<AgentGuardConfig> {
  const candidateFiles = [
    '.agentguardrc.json',
    '.agentguardrc',
    'agentguard.config.json',
  ];

  let configOverrides: Partial<AgentGuardConfig> = {};

  for (const file of candidateFiles) {
    const fullPath = path.resolve(cwd, file);
    if (fs.existsSync(fullPath)) {
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        configOverrides = JSON.parse(content) as Partial<AgentGuardConfig>;
        break;
      } catch {
        // Fall back gracefully if JSON has syntax errors
      }
    }
  }

  // Automatically read .gitignore entries
  const gitignorePatterns: string[] = [];
  const gitignorePath = path.resolve(cwd, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    try {
      const lines = fs.readFileSync(gitignorePath, 'utf-8').split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          gitignorePatterns.push(trimmed);
        }
      }
    } catch {
      // Ignore reading errors gracefully
    }
  }

  // Automatically read .agentguardignore entries if present
  const agentguardIgnorePatterns: string[] = [];
  const agentguardIgnorePath = path.resolve(cwd, '.agentguardignore');
  if (fs.existsSync(agentguardIgnorePath)) {
    try {
      const lines = fs.readFileSync(agentguardIgnorePath, 'utf-8').split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          agentguardIgnorePatterns.push(trimmed);
        }
      }
    } catch {
      // Ignore reading errors gracefully
    }
  }

  const combinedIgnores = Array.from(
    new Set([
      ...DEFAULT_CONFIG.ignorePaths,
      ...(Array.isArray(configOverrides.ignorePaths) ? configOverrides.ignorePaths : []),
      ...gitignorePatterns,
      ...agentguardIgnorePatterns,
    ])
  );

  return {
    ignorePaths: combinedIgnores,
    disabledRules: Array.isArray(configOverrides.disabledRules) ? configOverrides.disabledRules : [],
    severityOverrides: configOverrides.severityOverrides || {},
    minEntropy:
      typeof configOverrides.minEntropy === 'number'
        ? configOverrides.minEntropy
        : DEFAULT_CONFIG.minEntropy,
    failThreshold: configOverrides.failThreshold || DEFAULT_CONFIG.failThreshold,
  };
}
