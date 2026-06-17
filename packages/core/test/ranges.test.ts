import { describe, expect, it } from 'vitest';
import { isVersionAffected, nearestFix, vulnerabilityAffects } from '../src/match/ranges.js';
import type { OsvAffected, OsvEvent, OsvVulnerability } from '../src/types.js';

const range = (events: OsvEvent[]): OsvAffected => ({
  package: { ecosystem: 'npm', name: 'pkg' },
  ranges: [{ type: 'SEMVER', events }],
});

describe('isVersionAffected — event sweep', () => {
  it('introduced + fixed: affected up to (but not including) the fix', () => {
    const affected = range([{ introduced: '1.0.0' }, { fixed: '2.0.0' }]);
    expect(isVersionAffected('0.9.0', affected)).toBe(false);
    expect(isVersionAffected('1.0.0', affected)).toBe(true);
    expect(isVersionAffected('1.9.9', affected)).toBe(true);
    expect(isVersionAffected('2.0.0', affected)).toBe(false); // fixed is exclusive
    expect(isVersionAffected('2.1.0', affected)).toBe(false);
  });

  it('introduced:0 means affected from the beginning', () => {
    const affected = range([{ introduced: '0' }, { fixed: '1.5.0' }]);
    expect(isVersionAffected('0.0.1', affected)).toBe(true);
    expect(isVersionAffected('1.4.9', affected)).toBe(true);
    expect(isVersionAffected('1.5.0', affected)).toBe(false);
  });

  it('last_affected is inclusive', () => {
    const affected = range([{ introduced: '1.0.0' }, { last_affected: '1.5.0' }]);
    expect(isVersionAffected('1.5.0', affected)).toBe(true);
    expect(isVersionAffected('1.5.1', affected)).toBe(false);
  });

  it('no-fix-yet (introduced only) stays affected', () => {
    const affected = range([{ introduced: '1.0.0' }]);
    expect(isVersionAffected('99.0.0', affected)).toBe(true);
    expect(isVersionAffected('0.1.0', affected)).toBe(false);
  });

  it('honors enumerated versions exactly', () => {
    const affected: OsvAffected = {
      package: { ecosystem: 'npm', name: 'pkg' },
      versions: ['1.2.3', '1.2.4'],
    };
    expect(isVersionAffected('1.2.3', affected)).toBe(true);
    expect(isVersionAffected('1.2.5', affected)).toBe(false);
  });

  it('multiple introduced/fixed pairs (re-introduced vulnerability)', () => {
    const affected = range([
      { introduced: '1.0.0' },
      { fixed: '1.2.0' },
      { introduced: '1.5.0' },
      { fixed: '1.6.0' },
    ]);
    expect(isVersionAffected('1.1.0', affected)).toBe(true);
    expect(isVersionAffected('1.3.0', affected)).toBe(false); // patched window
    expect(isVersionAffected('1.5.5', affected)).toBe(true);
    expect(isVersionAffected('1.6.0', affected)).toBe(false);
  });

  it('handles unsorted events', () => {
    const affected = range([{ fixed: '2.0.0' }, { introduced: '1.0.0' }]);
    expect(isVersionAffected('1.5.0', affected)).toBe(true);
    expect(isVersionAffected('2.0.0', affected)).toBe(false);
  });

  it('prerelease versions compare below their release', () => {
    const affected = range([{ introduced: '1.0.0' }, { fixed: '2.0.0' }]);
    expect(isVersionAffected('2.0.0-beta.1', affected)).toBe(true); // still < 2.0.0
    expect(isVersionAffected('0.9.0-rc.1', affected)).toBe(false);
  });
});

describe('vulnerabilityAffects', () => {
  const vuln: OsvVulnerability = {
    id: 'GHSA-xxxx',
    affected: [
      {
        package: { ecosystem: 'npm', name: 'pkg' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.4.0' }] }],
      },
    ],
  };

  it('matches the right package name and collects fixed versions', () => {
    const match = vulnerabilityAffects('pkg', '1.2.0', vuln);
    expect(match.affected).toBe(true);
    expect(match.fixedVersions).toContain('1.4.0');
  });

  it('ignores a different package name', () => {
    expect(vulnerabilityAffects('other', '1.2.0', vuln).affected).toBe(false);
  });

  it('never matches a withdrawn advisory', () => {
    expect(
      vulnerabilityAffects('pkg', '1.2.0', { ...vuln, withdrawn: '2024-01-01T00:00:00Z' }).affected,
    ).toBe(false);
  });
});

describe('nearestFix', () => {
  it('returns the lowest fix strictly greater than the installed version', () => {
    expect(nearestFix('1.2.0', ['1.0.0', '1.4.0', '2.0.0'])).toBe('1.4.0');
  });
  it('returns undefined when no fix is newer', () => {
    expect(nearestFix('3.0.0', ['1.4.0', '2.0.0'])).toBeUndefined();
  });
});
