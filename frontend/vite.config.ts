/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Paths still served by Flask (port 3000) during development
const FLASK_PATHS = ['/api', '/login', '/logout', '/callback', '/static'];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(FLASK_PATHS.map((path) => [path, 'http://localhost:3000'])),
  },
  test: {
    // Custom jsdom env that restores native AbortController/AbortSignal so undici (msw +
    // react-router) accepts navigation Request signals. See tests/jsdom-undici.ts.
    environment: './tests/jsdom-undici.ts',
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.test.{ts,tsx}'],
    // The first test in a file pays jsdom + Mantine setup costs; on a loaded VM
    // that intermittently exceeds the 5s default.
    testTimeout: 15_000,
  },
});
