import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  platform: 'node',
  target: 'node20',
  dts: true,
  clean: true,
  sourcemap: true,
  // `fastify` is a peer dependency; never bundle it, and never bundle the
  // runtime deps either -- consumers resolve them from node_modules.
  external: ['fastify', 'fastify-plugin', '@fastify/error'],
})
