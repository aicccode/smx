const browserAndNode = {
  TextDecoder: 'readonly',
  TextEncoder: 'readonly',
  console: 'readonly',
  globalThis: 'readonly',
  performance: 'readonly',
  process: 'readonly',
  fetch: 'readonly',
  AbortSignal: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
}

export default [
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: browserAndNode,
    },
    rules: {
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-undef': 'error',
      'no-unused-vars': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
    },
  },
]
