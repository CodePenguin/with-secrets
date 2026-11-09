/// <reference types="vitest/config" />
import { readFileSync } from 'node:fs'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string }

// The build and the .NET assembly carry one version: MSBuild passes $(Version) as WS_VERSION; by hand it is package.json's.
const version = process.env.WS_VERSION ?? pkg.version

// dist/version.json: the frontend version, read by the publish check and shown in the application.
function versionFile(): Plugin {
  return {
    name: 'ws-version-file',
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'version.json', source: JSON.stringify({ version }) + '\n' })
    },
  }
}

export default defineConfig({
  // The application lives under /admin on the service's own origin (API: /api/v1; never served by the fallback).
  base: '/admin/',
  plugins: [react(), versionFile()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // No inline script of any kind: the page is served with script-src 'self'.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
  server: {
    // Development only: the API of a running service (with-secrets service --port 8765).
    proxy: { '/api': { target: 'http://localhost:8765', changeOrigin: false } },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: { modules: { classNameStrategy: 'non-scoped' } },
    restoreMocks: true,
  },
})
