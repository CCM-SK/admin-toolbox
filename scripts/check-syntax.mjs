import { readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const files = [];
async function collect(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.mjs')) && entry.name !== 'citrixadcRewrite.js') files.push(path);
  }
}
await collect(join(root, 'js'));
await collect(join(root, 'scripts'));
let failed = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed++;
    process.stderr.write(`${file}\n${result.stderr}`);
  }
}
if (failed) process.exit(1);
console.log(`Syntax check passed for ${files.length} JavaScript files (excluding the intentionally deferred, unused citrixadcRewrite.js from issue 6).`);
