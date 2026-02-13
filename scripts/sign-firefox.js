import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

function fail(message) {
  console.error(`[sign:firefox] ${message}`);
  process.exit(1);
}

const rootDir = process.cwd();
const firefoxDistDir = resolve(rootDir, 'dist', 'firefox');
const manifestPath = join(firefoxDistDir, 'manifest.json');
const artifactsDir = resolve(rootDir, 'dist', 'packages');

if (!existsSync(firefoxDistDir)) {
  fail('Missing dist/firefox. Run "npm run build" first.');
}

if (!existsSync(manifestPath)) {
  fail('Missing dist/firefox/manifest.json. Build output is incomplete.');
}

let manifest = null;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (error) {
  fail(`Could not read dist/firefox/manifest.json: ${error.message || error}`);
}

const geckoId = String(manifest?.browser_specific_settings?.gecko?.id || '').trim();
if (!geckoId) {
  fail('Missing browser_specific_settings.gecko.id in dist/firefox/manifest.json.');
}

const apiKey = String(process.env.WEB_EXT_API_KEY || process.env.AMO_JWT_ISSUER || '').trim();
const apiSecret = String(process.env.WEB_EXT_API_SECRET || process.env.AMO_JWT_SECRET || '').trim();
if (!apiKey || !apiSecret) {
  fail(
    'Missing AMO credentials. Set WEB_EXT_API_KEY + WEB_EXT_API_SECRET (or AMO_JWT_ISSUER + AMO_JWT_SECRET).'
  );
}

const signChannel = String(process.env.FIREFOX_SIGN_CHANNEL || 'unlisted').trim().toLowerCase();
mkdirSync(artifactsDir, { recursive: true });

const localWebExt = process.platform === 'win32'
  ? join(rootDir, 'node_modules', '.bin', 'web-ext.cmd')
  : join(rootDir, 'node_modules', '.bin', 'web-ext');

const command = existsSync(localWebExt)
  ? localWebExt
  : (process.platform === 'win32' ? 'npx.cmd' : 'npx');

const args = existsSync(localWebExt)
  ? ['sign']
  : ['--yes', 'web-ext', 'sign'];

args.push(
  '--source-dir', firefoxDistDir,
  '--artifacts-dir', artifactsDir,
  '--channel', signChannel,
  '--id', geckoId
);

const result = spawnSync(command, args, {
  stdio: 'inherit',
  env: {
    ...process.env,
    WEB_EXT_API_KEY: apiKey,
    WEB_EXT_API_SECRET: apiSecret
  }
});

if (result.status !== 0) {
  fail(`Signing failed (exit code ${result.status ?? 'unknown'}).`);
}

console.log(`[sign:firefox] Signing finished. Output directory: ${artifactsDir}`);
