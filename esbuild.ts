import { build } from 'esbuild';
import * as path from 'path';

const env = {
  'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV) || 'production',
  'process.env.DEBUG': JSON.stringify(process.env.DEBUG) || 'false',
  'process.env.NODE_DEBUG': JSON.stringify(process.env.NODE_DEBUG) || 'false',
}

build({
  entryPoints: [path.join(__dirname, 'src', 'index.ts')],
  outfile: path.join(__dirname, 'dist', 'index.js'),
  bundle: true,
  platform: 'browser',
  define: env,
  inject: [path.join(__dirname, 'polyfills', 'process.js')],
  alias: {
    'process': require.resolve('rollup-plugin-node-polyfills/polyfills/process-es6'),
    'buffer': require.resolve('buffer'),
    'util': require.resolve('rollup-plugin-node-polyfills/polyfills/util'),
    'events': require.resolve('events'),
    'stream': require.resolve('stream-browserify'),
    'crypto': require.resolve('crypto-browserify'),
    'assert': require.resolve('rollup-plugin-node-polyfills/polyfills/assert'),
    'vm': require.resolve('rollup-plugin-node-polyfills/polyfills/vm'),
  },
  sourcemap: true,
  format: 'esm',
});