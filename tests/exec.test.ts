/**
 * Command execution.
 *
 * The rule the file exists to enforce is "no shell, ever" - values from the
 * profile reach argv and nothing else - plus the failure modes that must not
 * look like success.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { OpenP2SError } from '../src/errors.ts';
import { RecordingCommandRunner, SystemCommandRunner } from '../src/platform/exec.ts';

const runner = new SystemCommandRunner();

describe('a timeout is a failure, not a result', () => {
  it('rejects when the child is killed for running too long', async () => {
    // `check: false` must not hand a timeout back as an ordinary result.
    await assert.rejects(
      () => runner.run('sleep', ['5'], { timeoutMs: 200 }),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /timed out after 200 ms/);
        return true;
      },
    );
  });

  it('rejects on timeout even with check explicitly false', async () => {
    // check governs exit codes. It has no say over whether we waited.
    await assert.rejects(
      () => runner.run('sleep', ['5'], { timeoutMs: 200, check: false }),
      /timed out/,
    );
  });

  it('does not reject a command that finishes inside its timeout', async () => {
    const result = await runner.run('true', [], { timeoutMs: 5_000 });
    assert.equal(result.code, 0);
  });
});

describe('timeout validation', () => {
  it('refuses a nonsensical timeout instead of acting on it', async () => {
    // setTimeout treats NaN and negatives as 0; Infinity disables it.
    for (const timeoutMs of [Number.NaN, 0, -1, Number.POSITIVE_INFINITY]) {
      await assert.rejects(
        () => runner.run('true', [], { timeoutMs }),
        /positive finite number/,
        `timeoutMs=${String(timeoutMs)} should be refused`,
      );
    }
  });
});

describe('exit codes and signals', () => {
  it('reports a non-zero exit code as data by default', async () => {
    const result = await runner.run('false', []);
    assert.equal(result.code, 1);
    assert.equal(result.signal, undefined);
  });

  it('rejects a non-zero exit code when check is set', async () => {
    await assert.rejects(() => runner.run('false', [], { check: true }), /exited with code 1/);
  });

  it('distinguishes a signal from an ordinary exit', async () => {
    // Every signal yields code -1, so the signal must be reported separately.
    const result = await runner.run('sh', ['-c', 'kill -TERM $$']);
    assert.equal(result.signal, 'SIGTERM');
  });

  it('names the signal when check rejects', async () => {
    await assert.rejects(
      () => runner.run('sh', ['-c', 'kill -TERM $$'], { check: true }),
      /terminated by SIGTERM/,
    );
  });
});

describe('no shell, ever', () => {
  it('passes metacharacters through as literal argv', async () => {
    // No command string is ever built, so this is an argument.
    const hostile = '; rm -rf / #$(whoami)`id`';
    const result = await runner.run('printf', ['%s', hostile]);
    assert.equal(result.stdout, hostile);
  });

  it('refuses an argument containing a NUL byte', async () => {
    // execve would truncate it: what ran would differ from what was validated.
    await assert.rejects(() => runner.run('printf', ['%s', 'a\0b']), /NUL byte/);
    await assert.rejects(() => runner.run('tr\0ue', []), /NUL byte/);
  });

  it('reports a missing executable clearly', async () => {
    await assert.rejects(
      () => runner.run('openp2s-no-such-command', []),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /failed to execute/);
        return true;
      },
    );
  });
});

describe('the recording runner matches the real one', () => {
  it('records exact argv', async () => {
    const recorder = new RecordingCommandRunner();
    await recorder.run('resolvectl', ['dns', 'tun0', '10.0.0.1']);
    assert.deepEqual(recorder.commandLines, ['resolvectl dns tun0 10.0.0.1']);
  });

  it('honours check the same way', async () => {
    const recorder = new RecordingCommandRunner(() => ({ code: 3, stdout: '', stderr: '' }));
    await assert.rejects(() => recorder.run('x', [], { check: true }), /exited with code 3/);
    const tolerated = await recorder.run('x', []);
    assert.equal(tolerated.code, 3);
  });
});
