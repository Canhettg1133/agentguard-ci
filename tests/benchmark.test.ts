import { describe, it, expect } from 'vitest';
import { runBenchmark } from '../src/benchmark/runner.js';

describe('Benchmark Suite & Accuracy Metrics', () => {
  it('achieves 100% Precision, 100% Recall, and 100% F1-score across ground truth dataset', () => {
    const metrics = runBenchmark();

    expect(metrics.total).toBe(35);
    expect(metrics.truePositives).toBe(23);
    expect(metrics.trueNegatives).toBe(12);
    expect(metrics.falsePositives).toBe(0); // Zero false alarms!
    expect(metrics.falseNegatives).toBe(0); // Zero missed true vulnerabilities!
    expect(metrics.precision).toBe(100);
    expect(metrics.recall).toBe(100);
    expect(metrics.f1Score).toBe(100);
    expect(metrics.avgLatencyMs).toBeLessThan(10); // Sub-millisecond execution

    expect(metrics.tiers).toBeDefined();
    expect(metrics.tiers!.secrets.passed).toBe(true);
    expect(metrics.tiers!.aiSafety.passed).toBe(true);
    expect(metrics.tiers!.mcp.passed).toBe(true);
    expect(metrics.tiers!.falsePositives.passed).toBe(true);
  });
});
