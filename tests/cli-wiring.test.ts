/**
 * Every declared flag reaches its command, and nothing reads a flag that does
 * not exist.
 *
 * `buildProgram()` maps commander's `Record<string, unknown>` onto each
 * command's options by hand:
 *
 *     ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {})
 *
 * Both halves fail silently and neither is a type error: a key commander never
 * sets spreads nothing, and a flag nobody reads still appears in `--help`.
 * Commander knows the attribute names it will set; the source says which ones
 * are read. The two sets must be equal, per command.
 *
 * Wiring only - what a command does with a flag is its own test's business.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { Command } from 'commander';
import { buildProgram } from '../src/cli/main.ts';

const SOURCE = readFileSync(join(import.meta.dirname, '..', 'src', 'cli', 'main.ts'), 'utf8');

/** Declaration order, parents before children - the order the source uses. */
function flatten(program: Command): Command[] {
  const flat: Command[] = [];
  for (const command of program.commands) {
    flat.push(command);
    flat.push(...command.commands);
  }
  return flat;
}

/** Each command's `.command('x')` .. next `.command(`, so options and action. */
function sourceBlocks(): Array<{ name: string; text: string }> {
  const body = SOURCE.slice(SOURCE.indexOf('export function buildProgram'));
  const marker = /\.command\('([a-z-]+)'\)/g;

  const starts: Array<{ name: string; index: number }> = [];
  let match: RegExpExecArray | null;
  while ((match = marker.exec(body)) !== null) {
    starts.push({ name: match[1] as string, index: match.index });
  }

  return starts.map((start, position) => ({
    name: start.name,
    text: body.slice(start.index, starts[position + 1]?.index ?? body.length),
  }));
}

/** Attribute names the mapping reads out of commander's bag. */
function keysReadIn(block: string): Set<string> {
  return new Set([...block.matchAll(/options\['([A-Za-z0-9_]+)'\]/g)].map((m) => m[1] as string));
}

/** Attribute names commander will actually set for this command. */
function keysDeclaredBy(command: Command): Set<string> {
  return new Set(command.options.map((option) => option.attributeName()));
}

const COMMANDS = flatten(buildProgram());
const BLOCKS = sourceBlocks();

describe('CLI wiring', () => {
  it('matches every source block to a declared command', () => {
    // Everything below pairs positionally, so a mismatch here invalidates it.
    assert.equal(
      BLOCKS.length,
      COMMANDS.length,
      `found ${BLOCKS.length} .command() blocks but ${COMMANDS.length} commands`,
    );
    assert.deepEqual(
      BLOCKS.map((block) => block.name),
      COMMANDS.map((command) => command.name()),
    );
  });

  for (const [position, command] of COMMANDS.entries()) {
    const block = BLOCKS[position];
    const path = command.parent?.name() === 'openp2s' ? command.name() : `auth ${command.name()}`;

    it(`\`${path}\` reads only flags it declares`, () => {
      assert.ok(block, 'no source block for this command');
      const declared = keysDeclaredBy(command);
      const unknown = [...keysReadIn(block.text)].filter((key) => !declared.has(key));

      assert.deepEqual(
        unknown,
        [],
        `${path} reads options[...] keys commander never sets: ${unknown.join(', ')}. ` +
          `Declared: ${[...declared].join(', ') || '(none)'}`,
      );
    });

    it(`\`${path}\` passes on every flag it declares`, () => {
      assert.ok(block, 'no source block for this command');
      const read = keysReadIn(block.text);
      const dropped = [...keysDeclaredBy(command)].filter((key) => !read.has(key));

      assert.deepEqual(
        dropped,
        [],
        `${path} declares flags it never passes to the command: ${dropped.join(', ')}. ` +
          'They appear in --help and do nothing.',
      );
    });
  }
});

describe('CLI surface', () => {
  it('keeps the documented commands', () => {
    // The README table and the man page list these; renaming one is breaking.
    assert.deepEqual(
      buildProgram()
        .commands.map((command) => command.name())
        .sort(),
      ['auth', 'connect', 'convert', 'disconnect', 'doctor', 'inspect', 'probe', 'status'].sort(),
    );
  });

  it('offers the global options every command mixes in', () => {
    // rootOptions() reads these off the root program via optsWithGlobals().
    const globals = new Set(buildProgram().options.map((option) => option.attributeName()));
    assert.ok(globals.has('verbose'), '--verbose must stay a global option');
    assert.ok(globals.has('quiet'), '--quiet must stay a global option');
  });
});
