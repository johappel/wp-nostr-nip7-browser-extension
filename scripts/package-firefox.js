import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';

function fail(message) {
  console.error(`[package:firefox] ${message}`);
  process.exit(1);
}

const rootDir = process.cwd();
const firefoxDistDir = resolve(rootDir, 'dist', 'firefox');
const manifestPath = join(firefoxDistDir, 'manifest.json');

if (!existsSync(firefoxDistDir)) {
  fail('Missing dist/firefox. Run "npm run build" first.');
}

if (!existsSync(manifestPath)) {
  fail('Missing dist/firefox/manifest.json. Build output is incomplete.');
}

let firefoxManifest = null;
try {
  firefoxManifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (error) {
  fail(`Could not read dist/firefox/manifest.json: ${error.message || error}`);
}

const geckoId = String(firefoxManifest?.browser_specific_settings?.gecko?.id || '').trim();
if (!geckoId) {
  fail('Missing browser_specific_settings.gecko.id in dist/firefox/manifest.json.');
}

const packageJsonPath = resolve(rootDir, 'package.json');
if (!existsSync(packageJsonPath)) {
  fail('Missing package.json.');
}

let version = '0.0.0';
try {
  const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  version = String(pkg.version || version);
} catch (error) {
  fail(`Could not read package.json: ${error.message || error}`);
}

const packagesDir = resolve(rootDir, 'dist', 'packages');
mkdirSync(packagesDir, { recursive: true });

const baseName = `wp-nostr-signer-firefox-${version}`;
const zipPath = join(packagesDir, `${baseName}.zip`);
const xpiPath = join(packagesDir, `${baseName}.xpi`);

rmSync(zipPath, { force: true });
rmSync(xpiPath, { force: true });

const tarArgs = ['-a', '-cf', zipPath, '-C', firefoxDistDir, '.'];
const tarResult = spawnSync('tar', tarArgs, { stdio: 'inherit' });
if (tarResult.status !== 0) {
  fail('Failed to create ZIP archive via "tar".');
}

copyFileSync(zipPath, xpiPath);

console.log(`[package:firefox] Created: ${xpiPath}`);
console.log('[package:firefox] Note: This XPI is unsigned. Firefox Release may show it as corrupt unless signed via AMO/web-ext sign.');
