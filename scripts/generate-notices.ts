/**
 * Build THIRD_PARTY_NOTICES from what is actually in the executable.
 *
 * A hand-maintained list of dependencies is a list of what someone remembered.
 * This reads esbuild's metafile instead. When the first version of this was
 * checked against reality, the hand-written list named 3 packages and the
 * bundle contained 26, three of which were not MIT at all.
 *
 * ## Package identity is a path, not a name
 *
 * npm may install several versions of one package, and nested copies under
 * other packages. Deduplicating by bare name would collapse `foo@1` and
 * `foo@2` into one entry, and reading `node_modules/foo/package.json` for a
 * module that actually came from `node_modules/a/node_modules/foo` would
 * report the wrong version and possibly the wrong licence. So each input is
 * resolved to its own enclosing package root, and identity is name@version.
 *
 * ## Fails closed
 *
 * A bundled package with no licence text stops the release. `"license": "MIT"`
 * in a package.json is a declaration, not the notice: MIT requires the
 * copyright line to travel with the code, and that lives in the licence file.
 * Where upstream genuinely ships none, an audited copy goes in
 * packaging/licenses/<name>@<version>.txt and is used explicitly.
 *
 * Usage:
 *   node scripts/generate-notices.ts <metafile> <buildinfo> <cli-buildinfo> \
 *        <openvpn-COPYING> <NODE_LICENSE> <source-tarball>
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

const [metafilePath, buildinfoPath, cliBuildinfoPath, copyingPath, nodeLicensePath, sourceTarball] =
  process.argv.slice(2);

const die: (message: string) => never = (message) => {
  console.error(`\nerror: ${message}\n`);
  process.exit(1);
};

if (
  !metafilePath ||
  !buildinfoPath ||
  !cliBuildinfoPath ||
  !copyingPath ||
  !nodeLicensePath ||
  !sourceTarball
) {
  console.error(
    'usage: generate-notices.ts <metafile> <buildinfo> <cli-buildinfo> ' +
      '<openvpn-COPYING> <NODE_LICENSE> <source-tarball>',
  );
  process.exit(2);
}

// The notices say these are distributed alongside. Check that they are, rather
// than promising a reader an artifact that was never assembled.
for (const [what, path] of [
  ['openvpn-COPYING', copyingPath],
  ['NODE_LICENSE', nodeLicensePath],
  ['the corresponding source tarball', sourceTarball],
] as const) {
  if (!existsSync(path)) {
    die(`the notices reference ${what}, but ${path} does not exist`);
  }
}

// ---- provenance files ----------------------------------------------------
//
// Strict: BUILDINFO is small, machine-written provenance. A malformed or
// duplicated line means something upstream of here went wrong, and silently
// taking the last value is how a release ends up describing the wrong build.
function readInfo(path: string): Record<string, string> {
  if (!existsSync(path)) die(`missing ${path}`);
  const info: Record<string, string> = {};

  readFileSync(path, 'utf8')
    .split('\n')
    .forEach((line, index) => {
      const where = `${path}:${index + 1}`;
      if (line.trim() === '' || line.trimStart().startsWith('#')) return;

      const at = line.indexOf('=');
      if (at <= 0) die(`${where}: malformed line, expected key=value`);

      const key = line.slice(0, at);
      if (key in info) die(`${where}: duplicate key '${key}'`);
      info[key] = line.slice(at + 1);
    });

  return info;
}

function requireInfo(info: Record<string, string>, key: string, source: string): string {
  const value = info[key];
  // Without this, a missing field reaches the document as the literal string
  // "undefined" and the release still succeeds.
  if (!value) die(`${source} has no '${key}'`);
  return value;
}

const buildinfo = readInfo(buildinfoPath);
const cliInfo = readInfo(cliBuildinfoPath);

// From the build record rather than from package.json in the current
// directory: the document must describe the build it was handed, and reading
// cwd made the generator silently dependent on where it was invoked from.
const openp2sVersion = requireInfo(cliInfo, 'openp2s_version', 'CLI-BUILDINFO');
const openvpnVersion = requireInfo(buildinfo, 'openvpn_version', 'BUILDINFO');
const nodeVersion = requireInfo(cliInfo, 'cli_node_version', 'CLI-BUILDINFO');
const nodeSha = requireInfo(cliInfo, 'cli_node_sha256', 'CLI-BUILDINFO');

// The OpenVPN section below names the patches that were applied. Checked
// rather than assumed - otherwise a differently-patched build would ship with
// notices describing a binary it is not.
const SHIPPED_STACK = 'long-credentials experimental-azure-compat';
const patchStack = requireInfo(buildinfo, 'patch_stack', 'BUILDINFO');
if (patchStack !== SHIPPED_STACK) {
  die(
    `these notices describe the shipped patch stack, but BUILDINFO reports ` +
      `'${patchStack}'. A release carries '${SHIPPED_STACK}'.`,
  );
}
if (requireInfo(buildinfo, 'azure_compat_available', 'BUILDINFO') !== '1') {
  die('BUILDINFO says the compat patch is not compiled in; that is not the shipped build');
}

// ---- what is actually in the bundle --------------------------------------
interface Metafile {
  outputs: Record<string, { inputs?: Record<string, { bytesInOutput?: number }> }>;
}

const metafile = JSON.parse(readFileSync(metafilePath, 'utf8')) as Metafile;

// outputs[].inputs, not the top-level inputs map. The latter lists everything
// esbuild *read*, including modules tree-shaken away to nothing - 28 of them
// here. Only what contributed bytes is actually distributed.
const contributing = new Set<string>();
for (const output of Object.values(metafile.outputs ?? {})) {
  for (const [input, detail] of Object.entries(output.inputs ?? {})) {
    if ((detail.bytesInOutput ?? 0) > 0) contributing.add(input);
  }
}
if (contributing.size === 0)
  die('the metafile records no contributing inputs, which cannot be right');

/**
 * The package directory an input actually came from.
 *
 * Walks up from the file to the nearest directory whose parent is
 * node_modules, so a nested copy resolves to its own root rather than to the
 * top-level package of the same name.
 */
function packageRootOf(input: string): string | undefined {
  const parts = input.split('/');
  for (let i = parts.length - 1; i > 0; i -= 1) {
    if (parts[i - 1] !== 'node_modules') continue;
    // A scoped package occupies two segments.
    const isScope = parts[i]?.startsWith('@') ?? false;
    const end = isScope ? i + 2 : i + 1;
    if (end > parts.length) return undefined;
    return parts.slice(0, end).join('/');
  }
  return undefined;
}

const roots = new Set<string>();
for (const input of contributing) {
  const root = packageRootOf(input);
  if (root) roots.add(root);
}
if (roots.size === 0) die('no bundled packages were found in the metafile');

// ---- licence texts -------------------------------------------------------
const LICENSE_NAMES = [
  'LICENSE',
  'LICENSE.md',
  'LICENSE.txt',
  'LICENCE',
  'LICENCE.md',
  'LICENCE.txt',
  'license',
  'license.md',
  'License',
  'License.md',
  'COPYING',
  'COPYING.txt',
];

/** Audited copies for packages that ship no licence file of their own. */
const OVERRIDE_DIR = join('packaging', 'licenses');

interface BundledPackage {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly license: string;
  readonly licenseText: string;
  readonly licenseSource: string;
  readonly notices: ReadonlyArray<{ readonly file: string; readonly text: string }>;
}

function findFile(dir: string, names: readonly string[]): string | undefined {
  return names.map((n) => join(dir, n)).find((p) => existsSync(p));
}

const packages = new Map<string, BundledPackage>();

for (const root of [...roots].sort()) {
  const manifestPath = join(root, 'package.json');
  if (!existsSync(manifestPath)) die(`${root} is bundled but has no package.json`);

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    name?: string;
    version?: string;
    license?: string;
    licenses?: Array<{ type?: string }>;
  };

  const name = manifest.name ?? basename(root);
  const version = manifest.version;
  if (!version) die(`${root} is bundled but declares no version`);

  const id = `${name}@${version}`;
  if (packages.has(id)) continue;

  const license =
    manifest.license ??
    (Array.isArray(manifest.licenses)
      ? manifest.licenses
          .map((l) => l.type ?? '')
          .filter(Boolean)
          .join(' OR ')
      : '');

  if (!license) die(`${id} is bundled into the executable but declares no license`);
  if (license.toUpperCase() === 'UNLICENSED') {
    die(`${id} is declared UNLICENSED; it must not be distributed`);
  }

  // "SEE LICENSE IN <file>" names the file explicitly; honouring the generic
  // search instead could pick up an unrelated file and attribute the wrong
  // terms.
  let licenseFile: string | undefined;
  let licenseSource: string;
  const seeLicenseIn = /^SEE LICEN[CS]E IN\s+(.+)$/i.exec(license);
  if (seeLicenseIn) {
    const named = join(root, seeLicenseIn[1]!.trim());
    if (!existsSync(named)) {
      die(`${id} declares "${license}" but ${named} does not exist`);
    }
    licenseFile = named;
    licenseSource = named;
  } else {
    licenseFile = findFile(root, LICENSE_NAMES);
    licenseSource = licenseFile ?? '';
  }

  if (!licenseFile) {
    // Fail closed, with an escape hatch that leaves a reviewable artifact in
    // the repository rather than a decision made silently at build time.
    const override = join(OVERRIDE_DIR, `${id.replace('/', '-')}.txt`);
    if (existsSync(override)) {
      licenseFile = override;
      licenseSource = `${override} (audited copy; upstream ships no licence file)`;
    } else {
      die(
        `${id} is bundled into the executable but ships no license text.\n` +
          `  Its package.json declares "${license}", which is a declaration, not the notice.\n` +
          `  Add an audited copy at ${override} if that is genuinely upstream's licence.`,
      );
    }
  }

  // NOTICE files carry attribution that the licence text itself may not, and
  // Apache-2.0 in particular requires them to travel with the distribution.
  const notices = readdirSync(root)
    .filter((entry) => /^(NOTICE|COPYRIGHT)(\.(txt|md))?$/i.test(entry))
    .sort()
    .map((entry) => ({ file: entry, text: readFileSync(join(root, entry), 'utf8').trim() }))
    .filter((n) => n.text.length > 0);

  packages.set(id, {
    id,
    name,
    version,
    license,
    licenseText: readFileSync(licenseFile, 'utf8').trim(),
    licenseSource,
    notices,
  });
}

const sorted = [...packages.values()].sort((a, b) => a.id.localeCompare(b.id));

const byLicense = sorted.reduce<Record<string, number>>((acc, p) => {
  acc[p.license] = (acc[p.license] ?? 0) + 1;
  return acc;
}, {});

const rule = (title: string): string =>
  `-- ${title} ${'-'.repeat(Math.max(0, 62 - title.length))}\n\n`;

let out = '';
out += 'THIRD PARTY NOTICES\n';
out += '===================\n\n';
out += `OpenP2S ${openp2sVersion} distributes the following third-party code.\n\n`;
out += "Generated from the build itself: the JavaScript list comes from esbuild's\n";
out += 'metafile, counting only modules that contributed bytes to the bundle, not\n';
out += 'from a hand-maintained list. Research attribution, which involves no\n';
out += 'distributed code, is in the project README rather than here.\n\n';

out += rule('OpenVPN');
out += 'Copyright (C) OpenVPN Inc. and contributors.\n\n';
out += `openvpn-openp2s is OpenVPN ${openvpnVersion}, built from the official release\n`;
out += 'tarball with two patches applied:\n\n';
out += `  patches/${openvpnVersion}/long-credentials.patch\n`;
out += `  patches/${openvpnVersion}/experimental-azure-compat.patch\n\n`;
out += 'The first changes two constants and nothing else, which is asserted line by\n';
out += 'line by scripts/check-patch-policy.sh. The second adds one OpenVPN option,\n';
out += '--experimental-azure-compat, which is inert unless a configuration asks for\n';
out += 'it and which a server cannot enable. The complete corresponding source\n';
out += `is distributed alongside this file as ${basename(sourceTarball)}.\n\n`;
out += 'OpenVPN is licensed under the GNU General Public License version 2, with\n';
out += 'linking exceptions including one for OpenSSL, against which this build is\n';
out += `linked. The complete upstream terms are in ${basename(copyingPath)}, distributed\n`;
out += 'alongside this file. That text is authoritative; nothing here narrows it.\n\n';

out += rule('Node.js');
out += 'The openp2s executable is a Node.js single executable application: a copy\n';
out += 'of the Node.js executable with the SEA application blob injected into it.\n';
out += 'It therefore contains the Node.js runtime in full.\n\n';
out += `  Node.js ${nodeVersion}\n`;
out += `  sha256  ${nodeSha}\n\n`;
out += 'Node bundles many externally maintained components under their own terms.\n';
out += `The complete text as published with that exact Node release is in\n`;
out += `${basename(nodeLicensePath)}, distributed alongside this file, and is authoritative;\n`;
out += 'it is not reproduced or summarised here.\n\n';

out += rule('Bundled JavaScript dependencies');
out += `${sorted.length} packages contribute code to the openp2s executable:\n\n`;
for (const p of sorted) {
  out += `  ${p.name.padEnd(30)} ${p.version.padEnd(12)} ${p.license}\n`;
}
out += `\nLicences present: ${Object.entries(byLicense)
  .sort()
  .map(([l, n]) => `${l} (${n})`)
  .join(', ')}\n\n`;

for (const p of sorted) {
  out += `--- ${p.name} ${p.version} (${p.license}) ---\n\n`;
  out += `${p.licenseText}\n\n`;
  for (const notice of p.notices) {
    out += `${p.name} ${p.version} - ${notice.file}:\n\n`;
    out += `${notice.text}\n\n`;
  }
}

process.stdout.write(out);
