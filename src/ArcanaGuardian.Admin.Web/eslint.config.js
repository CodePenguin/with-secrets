import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import reactHooks from 'eslint-plugin-react-hooks'

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'src/api/schema.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  jsxA11y.flatConfigs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      // Focus is placed on purpose inside modal dialogs (the first field, the one next action); on the page itself nothing takes focus by itself.
      'jsx-a11y/no-autofocus': ['error', { ignoreNonDOM: true }],
      // No inline styles (the page's CSP has no 'unsafe-inline' for styles) and no storage of anything in the browser.
      'no-restricted-properties': [
        'error',
        { object: 'window', property: 'localStorage', message: 'Nothing is kept in browser storage.' },
        { object: 'window', property: 'sessionStorage', message: 'Nothing is kept in browser storage.' },
      ],
      'no-restricted-globals': ['error', { name: 'localStorage', message: 'Nothing is kept in browser storage.' }, { name: 'sessionStorage', message: 'Nothing is kept in browser storage.' }],
      'no-restricted-syntax': ['error', { selector: 'JSXAttribute[name.name="style"]', message: 'No inline style: it is blocked by the Content Security Policy. Use a CSS module.' }, { selector: 'JSXAttribute[name.name="dangerouslySetInnerHTML"]', message: 'Never render HTML from data.' }],
    },
  },
  {
    // The tests assert that nothing was stored in the browser, so they may name the storage objects.
    files: ['src/**/*.test.{ts,tsx}'],
    rules: { 'no-restricted-globals': 'off' },
  },
  {
    files: ['scripts/**/*.mjs', 'vite.config.ts', 'eslint.config.js'],
    languageOptions: { globals: globals.node },
  },
)
