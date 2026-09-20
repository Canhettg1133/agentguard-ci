import { describe, it, expect } from 'vitest';
import { calculateShannonEntropy, isHighEntropy } from '../src/core/entropy.js';

describe('Shannon Entropy Calculator', () => {
  it('returns 0 for empty or null strings', () => {
    expect(calculateShannonEntropy('')).toBe(0);
  });

  it('calculates low entropy for repetitive sequences', () => {
    const lowEntropyStr = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const entropy = calculateShannonEntropy(lowEntropyStr);
    expect(entropy).toBe(0);
    expect(isHighEntropy(lowEntropyStr)).toBe(false);
  });

  it('calculates high entropy for cryptographic tokens', () => {
    // Standard random base64 string
    const highEntropyKey = 'sk-proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ';
    const entropy = calculateShannonEntropy(highEntropyKey);
    expect(entropy).toBeGreaterThan(4.0);
    expect(isHighEntropy(highEntropyKey)).toBe(true);
  });

  it('correctly filters out dummy keys that would cause false positives', () => {
    const dummyKey1 = 'sk-proj-11111111111111111111111111111111';
    const dummyKey2 = 'sk-proj-abcdefghabcdefghabcdefghabcdefgh';
    expect(isHighEntropy(dummyKey1)).toBe(false);
    expect(isHighEntropy(dummyKey2)).toBe(false);
  });
});
