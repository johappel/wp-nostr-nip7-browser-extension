# TASK-07: Build Pipeline

## Ziel
nostr-tools als ES Module in MV3 Service Worker bundeln. Chrome + Firefox Kompatibilität.

## package.json

```json
{
  "name": "wp-nostr-nip7-extension",
  "type": "module",
  "scripts": {
    "build": "rollup -c",
    "build:firefox": "rollup -c --environment TARGET:firefox"
  },
  "dependencies": {
    "nostr-tools": "^2.7.0"
  },
  "devDependencies": {
    "@rollup/plugin-node-resolve": "^15.0.0",
    "@rollup/plugin-commonjs": "^25.0.0",
    "rollup": "^4.0.0"
  }
}
```

## rollup.config.js

```javascript
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

const isFirefox = process.env.TARGET === 'firefox';
const outDir = isFirefox ? 'dist/firefox' : 'dist/chrome';

export default [
  {
    input: 'src/background.js',
    output: { file: `${outDir}/background.js`, format: 'es' },
    plugins: [resolve({ browser: true }), commonjs()]
  },
  {
    input: 'src/inpage.js',
    output: { file: `${outDir}/inpage.js`, format: 'iife' }
  }
];
```

## manifest.firefox.json

```json
{
  "manifest_version": 3,
  "name": "WordPress Nostr Signer",
  "version": "1.0.0",
  "background": {
    "scripts": ["background.js"],
    "type": "module"
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "nostr-signer@wordpress.org",
      "strict_min_version": "109.0"
    }
  }
}
```

## Akzeptanzkriterien

- [ ] `npm run build` erzeugt Chrome-Extension
- [ ] `npm run build:firefox` erzeugt Firefox-Extension
- [ ] nostr-tools Imports sind im Bundle aufgelöst
