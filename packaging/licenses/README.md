# Audited licence copies

`scripts/generate-notices.ts` fails the release when a package that contributes
code to the executable ships no licence text. `"license": "MIT"` in a
package.json is a _declaration_; MIT itself requires the copyright notice to
travel with the code, and that lives in the licence file.

Occasionally upstream genuinely omits the file from its npm tarball — usually
because `files` in package.json does not list it. Rather than letting the
generator paper over that at build time, an audited copy goes here, named
`<package>@<version>.txt` (a `/` in a scoped name becomes `-`).

Each file must begin with a comment recording:

- where the licence was determined from,
- who the copyright holder is and on what evidence,
- the date of the audit.

Adding a file here is a deliberate, reviewable act. Do not add one to make a
build pass without establishing what upstream's licence actually is.
