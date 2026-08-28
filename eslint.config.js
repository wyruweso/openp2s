// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['build/**', 'node_modules/**', 'patches/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // allowDefaultProject lets this config file lint itself; it is not
        // in tsconfig.json because tsconfig covers src, tests and scripts.
        projectService: { allowDefaultProject: ['eslint.config.js'] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Two of the three unsafe-* rules are on. The old blanket exemption was
      // justified as "we narrow unknown explicitly", which was not what these
      // rules object to - they catch `any` propagating, and explicit narrowing
      // from `unknown` satisfies them. Measured against the tree, member-access
      // and argument report nothing at all, so they stay on and will catch the
      // next `any` that escapes a boundary.
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',

      // This one has a single violation, spreading an `any` from a test
      // helper's return type. Left off rather than turned on with an inline
      // disable, so the count is visible here instead of buried: fix the
      // helper's typing and this can be 'error' too.
      '@typescript-eslint/no-unsafe-assignment': 'off',

      // Unused args are allowed when prefixed with _, which is how the
      // interface implementations mark parameters they deliberately ignore.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],

      // A VPN client should not be firing promises it does not await. The
      // node:test entry points return promises the runner owns, so they are
      // declared safe rather than the rule being switched off.
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          allowForKnownSafeCalls: [
            {
              from: 'package',
              package: 'node:test',
              name: ['describe', 'it', 'test', 'before', 'after', 'beforeEach', 'afterEach'],
            },
          ],
        },
      ],
      '@typescript-eslint/await-thenable': 'error',

      // Catch clauses legitimately ignore the error on cleanup paths.
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  {
    // Tests assert on loosely typed fixtures and shapes, and their fakes
    // implement async interfaces synchronously on purpose.
    files: ['tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/require-await': 'off',
    },
  },
);
