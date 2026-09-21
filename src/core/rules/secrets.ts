import { Finding, Rule } from '../types.js';
import { calculateShannonEntropy, isHighEntropy } from '../entropy.js';

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  description: string;
  severity: 'critical' | 'high';
  suggestedFix: string;
  requiresEntropyCheck?: boolean;
  cweId?: string;
}

const isPlaceholder = (val: string): boolean => {
  const lower = val.toLowerCase();
  return (
    lower.includes('placeholder') ||
    lower.includes('your_') ||
    lower.includes('your-') ||
    lower.includes('example') ||
    lower.includes('sample') ||
    lower.includes('xxxx') ||
    lower.includes('test_') ||
    lower.includes('mock_') ||
    lower.includes('<your') ||
    lower.includes('${') ||
    lower.includes('process.env')
  );
};

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'SEC-001',
    name: 'OpenAI API Key Leak',
    regex: /\b(sk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,})\b/g,
    description: 'Detected a live OpenAI API key committed into source code.',
    severity: 'critical',
    suggestedFix: 'Move this key to an environment variable (.env) or GitHub Secrets (e.g. process.env.OPENAI_API_KEY).',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-002',
    name: 'Anthropic Claude API Key Leak',
    regex: /\b(sk-ant-[a-zA-Z0-9_-]{32,})\b/g,
    description: 'Detected an Anthropic Claude API key committed into source code.',
    severity: 'critical',
    suggestedFix: 'Use process.env.ANTHROPIC_API_KEY or secret management instead of hardcoding.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-003',
    name: 'Google Gemini / Cloud API Key',
    regex: /\b(AIzaSy[a-zA-Z0-9_-]{33})\b/g,
    description: 'Detected a Google Cloud / Gemini AI Studio API key in source code.',
    severity: 'critical',
    suggestedFix: 'Rotate this key immediately in Google Cloud Console and store it in environment variables.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-004',
    name: 'GitHub Personal Access Token',
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g,
    description: 'Detected a GitHub Personal Access Token (PAT). Anyone with this token can access your repositories.',
    severity: 'critical',
    suggestedFix: 'Revoke this token immediately on GitHub Settings -> Developer Settings -> Personal access tokens.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-005',
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    description: 'Detected an AWS Access Key ID. Hardcoded AWS credentials lead to severe cloud infrastructure takeovers.',
    severity: 'high',
    suggestedFix: 'Use AWS IAM Roles, AWS Secrets Manager, or ~/.aws/credentials instead of hardcoded keys.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-006',
    name: 'Private RSA / OpenSSH Key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    description: 'Detected an unencrypted private cryptographic key in plaintext source code.',
    severity: 'critical',
    suggestedFix: 'Never commit private keys to version control. Add them to .gitignore and use key vaults.',
    requiresEntropyCheck: false,
  },
  {
    id: 'SEC-007',
    name: 'Database Connection String with Credentials',
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_!@#$%^&*()+=~-]+@[a-zA-Z0-9.-]+:[0-9]{2,5}\/[a-zA-Z0-9_.-]+/g,
    description: 'Database connection URI contains embedded plaintext username and password.',
    severity: 'critical',
    suggestedFix: 'Store the connection string in DATABASE_URL environment variable.',
    requiresEntropyCheck: false,
  },
  {
    id: 'SEC-008',
    name: 'Hugging Face API Token',
    regex: /\b(hf_[a-zA-Z0-9]{34})\b/g,
    description: 'Detected a Hugging Face API token in source code.',
    severity: 'high',
    suggestedFix: 'Store in HF_TOKEN environment variable.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-009',
    name: 'Stripe Secret API Key',
    regex: /\b([sr]k_live_[0-9a-zA-Z]{24,})\b/g,
    description: 'Detected a live Stripe production secret key. Risk of unauthorized financial transactions.',
    severity: 'critical',
    suggestedFix: 'Revoke key in Stripe Dashboard and store in process.env.STRIPE_SECRET_KEY.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-010',
    name: 'Slack Incoming Webhook / Bot Token',
    regex: /\b(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    description: 'Detected a Slack webhook URL or bot authentication token.',
    severity: 'high',
    suggestedFix: 'Move Slack webhook to environment variables or GitHub Secrets.',
    requiresEntropyCheck: false,
  },
  {
    id: 'SEC-011',
    name: 'Groq API Key Leak',
    regex: /\b(gsk_[a-zA-Z0-9]{48,64})\b/g,
    description: 'Detected a live Groq API key committed into source code.',
    severity: 'critical',
    suggestedFix: 'Move Groq API key to GROQ_API_KEY environment variable.',
    requiresEntropyCheck: true,
  },
  {
    id: 'SEC-012',
    name: 'LangSmith / LangChain API Key Leak',
    regex: /\b(lsv2_pt_[a-zA-Z0-9_]{32,})\b/g,
    description: 'Detected a live LangChain / LangSmith API key committed into source code.',
    severity: 'critical',
    suggestedFix: 'Store in LANGCHAIN_API_KEY environment variable or GitHub Secrets.',
    requiresEntropyCheck: true,
  },
];

export const secretRules: Rule[] = SECRET_PATTERNS.map((pattern) => ({
  id: pattern.id,
  name: pattern.name,
  description: pattern.description,
  severity: pattern.severity,
  category: 'secret',
  cweId: pattern.cweId || 'CWE-798',
  match: (content: string, filePath: string): Finding[] => {
    const norm = filePath.replace(/\\/g, '/');
    if (
      norm.endsWith('src/core/rules/secrets.ts') ||
      norm.endsWith('fixtures.ts')
    ) {
      return [];
    }

    const isTestFile =
      filePath.includes('.test.') ||
      filePath.includes('.spec.') ||
      filePath.includes('/fixtures/') ||
      filePath.includes('\\fixtures\\');

    const lines = content.split(/\r?\n/);
    const findings: Finding[] = [];

    lines.forEach((line, idx) => {
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.regex.exec(line)) !== null) {
        const captured = match[1] || match[0];
        if (isPlaceholder(captured) || isPlaceholder(line)) {
          continue;
        }

        // Shannon entropy verification
        const entropyVal = calculateShannonEntropy(captured);
        if (pattern.requiresEntropyCheck) {
          // If the token is low entropy (e.g. repeated characters or predictable dummy), skip
          if (!isHighEntropy(captured, 3.0)) {
            continue;
          }
        }

        // In test files, if the line contains dummy/mock identifiers, skip
        if (isTestFile && (line.includes('mock') || line.includes('dummy') || line.includes('fake'))) {
          continue;
        }

        // Mask sensitive portion
        const masked =
          captured.length > 8
            ? captured.slice(0, 4) + '...' + captured.slice(-4)
            : '***';

        findings.push({
          id: `${pattern.id}-${idx + 1}`,
          ruleId: pattern.id,
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          category: 'secret',
          cweId: 'CWE-798',
          file: filePath,
          line: idx + 1,
          column: match.index + 1,
          snippet: line.replace(captured, masked).trim(),
          suggestedFix: pattern.suggestedFix,
          referenceUrl: 'https://cwe.mitre.org/data/definitions/798.html',
          entropy: Math.round(entropyVal * 100) / 100,
        });
      }
    });

    return findings;
  },
}));
