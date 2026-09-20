import { describe, it, expect } from 'vitest';
import { runBenchmark } from '../src/benchmark/runner.js';

describe('Benchmark Suite & Accuracy Metrics', () => {
  it('achieves 100% Precision, 100% Recall, and 100% F1-score across ground truth dataset', () => {
    const metrics = runBenchmark();

    expect(metrics.total).toBe(27);
    expect(metrics.truePositives).toBe(19);
    expect(metrics.trueNegatives).toBe(8);
    expect(metrics.falsePositives).toBe(0); // Zero false alarms!
    expect(metrics.falseNegatives).toBe(0); // Zero missed true vulnerabilities!
    expect(metrics.precision).toBe(100);
    expect(metrics.recall).toBe(100);
    expect(metrics.f1Score).toBe(100);
    expect(metrics.avgLatencyMs).toBeLessThan(10); // Sub-millisecond execution
  });
});
