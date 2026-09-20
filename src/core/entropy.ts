/**
 * Shannon Entropy Calculator for cryptographic key verification.
 * Formula: H(X) = -sum(P(x) * log2(P(x)))
 *
 * Real cryptographic keys (OpenAI sk-..., AWS, private keys) exhibit
 * high information entropy (> 3.2 for base64/hex characters), whereas
 * dummy/placeholder strings (e.g., "11111111", "abcdefghabcdefgh") have very low entropy.
 */

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const charFrequencies = new Map<string, number>();
  for (const char of str) {
    charFrequencies.set(char, (charFrequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of charFrequencies.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Determines whether a given token has sufficient entropy to be a true secret.
 * @param token The candidate secret string
 * @param threshold Minimum entropy threshold (default: 3.2 for typical API keys)
 */
export function isHighEntropy(token: string, threshold = 3.2): boolean {
  if (!token || token.length < 12) {
    return false;
  }

  // Remove standard prefixes that artificially skew character frequency
  const cleaned = token
    .replace(/^sk-(?:proj-|admin-|ant-)?/i, '')
    .replace(/^AIzaSy/i, '')
    .replace(/^AKIA/i, '')
    .replace(/^ghp_/i, '')
    .replace(/^github_pat_/i, '')
    .replace(/^sk_live_/i, '');

  if (cleaned.length < 8) {
    return false;
  }

  const entropy = calculateShannonEntropy(cleaned);
  return entropy >= threshold;
}
