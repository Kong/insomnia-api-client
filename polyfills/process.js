import processPolyfill from 'rollup-plugin-node-polyfills/polyfills/process-es6';

const p = typeof process === 'undefined' ? processPolyfill : process;

export {
  p as process
}