/**
 * How `openp2s disconnect` signals OpenVPN.
 *
 * OpenVPN runs as the user, so the signal goes directly and sudo is not asked:
 * a service's ExecStop has no terminal for a password. Elevation is kept only
 * for EPERM, a tunnel whose OpenVPN still runs as root.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { signalOpenvpn } from '../src/cli/commands/disconnect.ts';

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

describe('signalling OpenVPN on disconnect', () => {
  it('signals directly and never elevates when that works', async () => {
    const sent: string[] = [];
    let elevated = 0;
    await signalOpenvpn(1234, 'SIGTERM', {
      kill: (pid, signal) => sent.push(`${pid}:${signal}`),
      isRoot: false,
      elevated: async () => {
        elevated += 1;
      },
    });
    assert.deepEqual(sent, ['1234:SIGTERM']);
    assert.equal(elevated, 0);
  });

  it('elevates only on EPERM, for an OpenVPN still running as root', async () => {
    const elevated: string[] = [];
    await signalOpenvpn(1234, 'SIGKILL', {
      kill: () => {
        throw errno('EPERM');
      },
      isRoot: false,
      elevated: async (pid, signal) => {
        elevated.push(`${pid}:${signal}`);
      },
    });
    assert.deepEqual(elevated, ['1234:SIGKILL']);
  });

  it('does not elevate when the process is already gone', async () => {
    let elevated = 0;
    await assert.rejects(
      signalOpenvpn(1234, 'SIGTERM', {
        kill: () => {
          throw errno('ESRCH');
        },
        isRoot: false,
        elevated: async () => {
          elevated += 1;
        },
      }),
      { code: 'ESRCH' },
    );
    assert.equal(elevated, 0);
  });

  it('does not elevate as root', async () => {
    let elevated = 0;
    await assert.rejects(
      signalOpenvpn(1234, 'SIGTERM', {
        kill: () => {
          throw errno('EPERM');
        },
        isRoot: true,
        elevated: async () => {
          elevated += 1;
        },
      }),
      { code: 'EPERM' },
    );
    assert.equal(elevated, 0);
  });
});
