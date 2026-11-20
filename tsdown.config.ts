import { defineConfig } from 'tsdown'

/** The bundle identifier is also the exported plugin name. */
const PLUGIN_ID = 'dsh-local-browser-access'

export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'lib',
  format: 'esm',
  platform: 'node',
  target: 'es2022',
  fixedExtension: false,
  clean: true,
  dts: false,
  deps: {
    neverBundle: [
      '@deepseek-ai/cordis',
      '@deepseek-ai/dsh-client-connection',
      '@deepseek-ai/dsh-host-webserver',
    ],
  },
  name: `${PLUGIN_ID}/host`,
})
