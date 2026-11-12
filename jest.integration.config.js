/**
 * Integration tests: need Postgres, Redis and the generated secrets. Run them inside the
 * compose network with `npm run test:docker` (see docker-compose.test.yml).
 * @type {import('jest').Config}
 */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test/integration'],
  testMatch: ['**/*.test.ts'],
  testTimeout: 30000,
  maxWorkers: 1,
  transform: {
    '^.+\.ts$': [
      '@swc/jest',
      {
        jsc: { parser: { syntax: 'typescript' }, target: 'es2022' },
        module: { type: 'commonjs' },
      },
    ],
  },
  // Every client is closed in afterAll; this only guards CI against a hung driver socket.
  forceExit: true,
};
