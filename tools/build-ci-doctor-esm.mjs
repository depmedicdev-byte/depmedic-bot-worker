// Bundle ci-doctor's auditWorkflow into a Cloudflare-Worker-compatible ESM
// at src/ci-doctor-bundled.js. Re-run when ci-doctor changes.
import { build } from 'esbuild';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const CI_DOCTOR = path.resolve(__dirname, '../../ci-doctor/src/index.js');
const OUT = path.resolve(__dirname, '../src/ci-doctor-bundled.js');

const entry = path.resolve(__dirname, '_entry.mjs');
fs.writeFileSync(
  entry,
  `import cd from '${CI_DOCTOR.replace(/\\/g, '/')}';
export const auditWorkflow = cd.auditWorkflow;
export const summarize = cd.summarize;
export const rules = cd.rules;
`
);

await build({
  entryPoints: [entry],
  outfile: OUT,
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  minify: true,
  define: { 'process.env.NODE_ENV': '"production"' },
  external: ['node:fs', 'node:path'],
  banner: {
    js: `var process = { env: {} };
var require = (m) => {
  if (m === 'node:fs') return {};
  if (m === 'node:path') return { resolve: (...a) => a.join('/'), join: (...a) => a.join('/'), relative: (_, p) => p };
  throw new Error('missing module: ' + m);
};`,
  },
});

fs.unlinkSync(entry);
console.log('built ESM bundle at', OUT, fs.statSync(OUT).size, 'bytes');
