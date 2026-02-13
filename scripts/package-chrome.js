import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';

function fail(message) {
  console.error(`[package:chrome] ${message}`);
  process.exit(1);
}

const rootDir = process.cwd();
const chromeDistDir = resolve(rootDir, 'dist', 'chrome');
const manifestPath = join(chromeDistDir, 'manifest.json');

if (!existsSync(chromeDistDir)) {
  fail('Missing dist/chrome. Run "npm run build" first.');
}

if (!existsSync(manifestPath)) {
  fail('Missing dist/chrome/manifest.json. Build output is incomplete.');
}

let chromeManifest = null;
try {
  chromeManifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (error) {
  fail(`Could not read dist/chrome/manifest.json: ${error.message || error}`);
}

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

const manifestVersion = String(chromeManifest?.version || '').trim();
if (!manifestVersion) {
  fail('Missing "version" in dist/chrome/manifest.json.');
}
if (manifestVersion !== version) {
  fail(`Version mismatch: package.json=${version}, dist/chrome/manifest.json=${manifestVersion}`);
}

const packagesDir = resolve(rootDir, 'dist', 'packages');
mkdirSync(packagesDir, { recursive: true });

const baseName = `wp-nostr-signer-chrome-${version}`;
const zipPath = join(packagesDir, `${baseName}.zip`);

rmSync(zipPath, { force: true });

function escapeForSingleQuotedPs(value) {
  return String(value).replace(/'/g, "''");
}

function createZipWithPowerShell() {
  const sourcePath = escapeForSingleQuotedPs(chromeDistDir);
  const destinationPath = escapeForSingleQuotedPs(zipPath);
  const command = [
    '$ErrorActionPreference = "Stop";',
    `if (Test-Path -LiteralPath '${destinationPath}') { Remove-Item -LiteralPath '${destinationPath}' -Force }`,
    `Compress-Archive -Path (Join-Path '${sourcePath}' '*') -DestinationPath '${destinationPath}' -CompressionLevel Optimal`
  ].join(' ');

  const psExecutable = process.env.ComSpec
    ? 'powershell.exe'
    : 'powershell';
  return spawnSync(psExecutable, ['-NoProfile', '-Command', command], { stdio: 'inherit' });
}

function createZipWithTar() {
  const tarArgs = ['-a', '-cf', zipPath, '-C', chromeDistDir, '.'];
  return spawnSync('tar', tarArgs, { stdio: 'inherit' });
}

let zipResult = null;
if (process.platform === 'win32') {
  zipResult = createZipWithPowerShell();
  if (zipResult.status !== 0) {
    console.warn('[package:chrome] PowerShell Compress-Archive failed, falling back to tar.');
    zipResult = createZipWithTar();
  }
} else {
  zipResult = createZipWithTar();
}

if (zipResult.status !== 0 || !existsSync(zipPath)) {
  const detail = zipResult.error?.message ? ` (${zipResult.error.message})` : '';
  fail(`Failed to create Chrome ZIP archive${detail}.`);
}

console.log(`[package:chrome] Created: ${zipPath}`);
console.log('[package:chrome] Upload this ZIP in the Chrome Web Store Developer Dashboard.');
