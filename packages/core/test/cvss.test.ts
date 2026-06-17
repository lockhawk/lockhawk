import { describe, expect, it } from 'vitest';
import { levelFromScore, resolveSeverity, scoreFromVector } from '../src/score/cvss.js';
import type { OsvVulnerability } from '../src/types.js';

describe('scoreFromVector (CVSS v3.1)', () => {
  it('scores a classic critical vector (9.8)', () => {
    const result = scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(result?.score).toBe(9.8);
    expect(result?.level).toBe('critical');
  });

  it('scores a scope-changed vector (10.0)', () => {
    const result = scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(result?.score).toBe(10);
    expect(result?.level).toBe('critical');
  });

  it('scores a medium vector (4.3)', () => {
    const result = scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N');
    expect(result?.score).toBe(4.3);
    expect(result?.level).toBe('medium');
  });

  it('also accepts CVSS:3.0 headers', () => {
    expect(scoreFromVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')?.score).toBe(9.8);
  });

  // Expected values produced by the FIRST.org reference calculator.
  it.each([
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 10, 'critical'],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3, 'critical'],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', 6.9, 'medium'],
    ['CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L', 7, 'high'],
    ['CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N', 1, 'low'],
    ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0, 'none'],
  ])('scores CVSS v4.0 vector %s as %d', (vector, score, level) => {
    const result = scoreFromVector(vector as string);
    expect(result?.score).toBe(score);
    expect(result?.level).toBe(level);
    expect(result?.version).toBe('CVSS:4.0');
  });
});

describe('levelFromScore boundaries', () => {
  it('maps the CVSS bands', () => {
    expect(levelFromScore(0)).toBe('none');
    expect(levelFromScore(3.9)).toBe('low');
    expect(levelFromScore(4)).toBe('medium');
    expect(levelFromScore(6.9)).toBe('medium');
    expect(levelFromScore(7)).toBe('high');
    expect(levelFromScore(9)).toBe('critical');
  });
});

describe('resolveSeverity', () => {
  it('prefers a computed CVSS score and records provenance', () => {
    const vuln: OsvVulnerability = {
      id: 'GHSA-1',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    };
    const sev = resolveSeverity(vuln);
    expect(sev.source).toBe('cvss');
    expect(sev.level).toBe('critical');
    expect(sev.score).toBe(9.8);
  });

  it('falls back to the qualitative database severity', () => {
    const vuln: OsvVulnerability = { id: 'GHSA-2', database_specific: { severity: 'HIGH' } };
    const sev = resolveSeverity(vuln);
    expect(sev.source).toBe('database');
    expect(sev.level).toBe('high');
  });

  it('reports unknown when nothing is available', () => {
    expect(resolveSeverity({ id: 'GHSA-3' }).level).toBe('unknown');
  });

  it('takes the highest score across multiple vectors', () => {
    const vuln: OsvVulnerability = {
      id: 'GHSA-4',
      severity: [
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N' },
        { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
      ],
    };
    expect(resolveSeverity(vuln).level).toBe('critical');
  });
});
