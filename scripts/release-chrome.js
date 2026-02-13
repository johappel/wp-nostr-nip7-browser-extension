import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

function fail(message) {
  console.error(`[release:chrome] ${message}`);
  process.exit(1);
}

const rootDir = process.cwd();
const packageJsonPath = resolve(rootDir, 'package.json');
if (!existsSync(packageJsonPath)) {
  fail('Missing package.json.');
}

let version = '0.0.0';
try {
  const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  version = String(pkg.version || version).trim();
} catch (error) {
  fail(`Could not read package.json: ${error.message || error}`);
}

const zipPath = resolve(rootDir, 'dist', 'packages', `wp-nostr-signer-chrome-${version}.zip`);
if (!existsSync(zipPath)) {
  fail(`Missing ${zipPath}. Run "npm run package:chrome" first.`);
}

console.log('[release:chrome] Chrome release checklist');
console.log(`1. Upload ZIP: ${zipPath}`);
console.log('2. Open Chrome Web Store Developer Dashboard: https://chrome.google.com/webstore/devconsole');
console.log('3. Create a new item or upload a new package for the existing item.');
console.log(`4. Ensure listing version matches ${version}.`);
console.log('5. Add release notes, submit for review, then publish after approval.');
