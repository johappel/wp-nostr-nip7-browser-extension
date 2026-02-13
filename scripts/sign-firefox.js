import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

function fail(message) {
  console.error(`[sign:firefox] ${message}`);
  process.exit(1);
}

function normalizeEnvToken(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const quoted = raw.match(/^(['"])(.*)\1$/);
  return quoted ? quoted[2].trim() : raw;
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

const apiKey = normalizeEnvToken(process.env.WEB_EXT_API_KEY || process.env.AMO_JWT_ISSUER);
const apiSecret = normalizeEnvToken(process.env.WEB_EXT_API_SECRET || process.env.AMO_JWT_SECRET);
if (!apiKey || !apiSecret) {
  fail(
    'Missing AMO credentials. Set WEB_EXT_API_KEY + WEB_EXT_API_SECRET (or AMO_JWT_ISSUER + AMO_JWT_SECRET).'
  );
}
if (/\s/.test(apiKey)) {
  fail('WEB_EXT_API_KEY appears malformed (contains whitespace). Copy/paste issuer again from AMO.');
}
if (/\s/.test(apiSecret)) {
  fail('WEB_EXT_API_SECRET appears malformed (contains whitespace). Copy/paste secret again from AMO.');
}

const signChannel = String(process.env.FIREFOX_SIGN_CHANNEL || 'unlisted').trim().toLowerCase();
mkdirSync(artifactsDir, { recursive: true });

const localWebExt = process.platform === 'win32'
  ? join(rootDir, 'node_modules', '.bin', 'web-ext.cmd')
  : join(rootDir, 'node_modules', '.bin', 'web-ext');

const signArgs = [
  '--source-dir', firefoxDistDir,
  '--artifacts-dir', artifactsDir,
  '--channel', signChannel
];

const candidates = [];
if (existsSync(localWebExt)) {
  candidates.push({
    label: 'local web-ext',
    command: localWebExt,
    args: ['sign', ...signArgs]
  });
}

const npmExecPath = String(process.env.npm_execpath || '').trim();
if (npmExecPath) {
  candidates.push({
    label: 'npm exec web-ext',
    command: process.execPath,
    args: [npmExecPath, 'exec', '--yes', '--', 'web-ext', 'sign', ...signArgs]
  });
}

candidates.push({
  label: 'npx web-ext',
  command: process.platform === 'win32' ? 'npx.cmd' : 'npx',
  args: ['--yes', 'web-ext', 'sign', ...signArgs]
});

let lastFailure = null;
let signed = false;
for (const candidate of candidates) {
  console.log(`[sign:firefox] Trying signer via ${candidate.label}`);
  const result = spawnSync(candidate.command, candidate.args, {
    stdio: 'inherit',
    env: {
      ...process.env,
      WEB_EXT_API_KEY: apiKey,
      WEB_EXT_API_SECRET: apiSecret
    }
  });

  if (result.status === 0) {
    signed = true;
    break;
  }

  lastFailure = {
    label: candidate.label,
    command: candidate.command,
    error: result.error,
    status: result.status,
    signal: result.signal
  };

  if (result.error && result.error.code === 'ENOENT') {
    console.warn(`[sign:firefox] ${candidate.label} not available in PATH, trying next fallback.`);
    continue;
  }
  break;
}

if (!signed) {
  if (lastFailure?.error) {
    fail(
      `Signing failed via ${lastFailure.label}: ${lastFailure.error.message || lastFailure.error} `
      + `(command: ${lastFailure.command}).`
    );
  }
  fail(
    `Signing failed via ${lastFailure?.label || 'unknown signer'} `
    + `(exit code ${lastFailure?.status ?? 'unknown'}, signal ${lastFailure?.signal ?? 'none'}).`
  );
}

console.log(`[sign:firefox] Signing finished. Output directory: ${artifactsDir}`);
