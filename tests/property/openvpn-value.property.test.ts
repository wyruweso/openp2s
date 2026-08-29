/**
 * Properties of openVpnValue(), the escaping guard for directive values.
 *
 * The example-based tests in openvpn-config.test.ts pin the hostile inputs we
 * thought of. This file states the guarantee for the ones nobody thought of,
 * which is the case that matters: the config is read by a process running as
 * root, so "no input can add a directive" has to hold over every string
 * rather than over a list.
 *
 * The seed is deliberately not pinned. fast-check prints the failing seed and
 * a shrunk counterexample, so a failure is reproducible; fixing the seed up
 * front would only turn this into a slower way of writing the fixed examples
 * that already exist.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import fc from 'fast-check';
import { OpenP2SError } from '../../src/errors.ts';
import { openVpnValue } from '../../src/openvpn/config.ts';

/** The characters that decide which branch openVpnValue takes, plus filler. */
const SIGNIFICANT = [
  ' ',
  '\t',
  '"',
  "'",
  '#',
  ';',
  '\\',
  '/',
  '.',
  '-',
  'a',
  'b',
  '\n',
  '\r',
  '\u0000',
  '\u001b',
];

/** The four openVpnValue rejects outright, because quoting cannot contain them. */
const CONTROL = ['\n', '\r', '\u0000', '\u001b'] as const;

/** Weighted towards the significant characters, but not limited to them. */
const configValue = fc.oneof(
  fc.string({ unit: fc.constantFrom(...SIGNIFICANT), maxLength: 24 }),
  fc.string({ maxLength: 24 }),
  fc.string({ unit: 'binary', maxLength: 12 }),
);

/**
 * Read a rendered value back, written from OpenVPN's quoting rules rather
 * than from openVpnValue(). The inverse must not share code with the
 * renderer: escaping is only correct if something else can recover the
 * original from what it produced.
 */
function readOpenVpnValue(rendered: string): string {
  if (!rendered.startsWith('"')) {
    return rendered;
  }

  let out = '';
  let index = 1;
  while (index < rendered.length) {
    const char = rendered.charAt(index);
    if (char === '\\') {
      out += rendered.charAt(index + 1);
      index += 2;
      continue;
    }
    if (char === '"') {
      assert.equal(index, rendered.length - 1, 'the closing quote must end the value');
      return out;
    }
    out += char;
    index += 1;
  }
  throw new Error('unterminated quoted value');
}

/** Rendered, or undefined when rejected - a rejection is a valid outcome. */
function render(input: string): string | undefined {
  try {
    return openVpnValue(input, '--test');
  } catch (error) {
    assert.ok(error instanceof OpenP2SError, `unexpected ${String(error)}`);
    return undefined;
  }
}

describe('openVpnValue: properties', () => {
  it('escapes losslessly: every accepted value reads back unchanged', () => {
    fc.assert(
      fc.property(configValue, (input) => {
        const rendered = render(input);
        if (rendered !== undefined) {
          assert.equal(readOpenVpnValue(rendered), input);
        }
      }),
    );
  });

  it('keeps every accepted value on the single line of its directive', () => {
    fc.assert(
      fc.property(configValue, (input) => {
        const rendered = render(input);
        if (rendered !== undefined) {
          const line = `ca ${rendered}`;
          assert.ok(!line.includes('\n'), 'a value may never introduce a line');
          assert.ok(!line.includes('\r'), 'a value may never introduce a line');
        }
      }),
    );
  });

  it('rejects a control character wherever it appears', () => {
    fc.assert(
      fc.property(
        configValue,
        fc.constantFrom(...CONTROL),
        configValue,
        (before, control, after) => {
          assert.throws(() => openVpnValue(`${before}${control}${after}`, '--test'), OpenP2SError);
        },
      ),
    );
  });
});
