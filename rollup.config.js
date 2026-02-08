import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import copy from 'rollup-plugin-copy';

const commonPlugins = [
  resolve(),
  commonjs()
];

// Dateien, die 1:1 kopiert werden sollen
const staticFiles = [
  'content.js',
  'inpage.js',
  'popup.html',
  'popup.js',
  'popup.css',
  'dialog.html',
  'dialog.js',
  'dialog.css',
  'icons'
];

export default [
  // Chrome Build
  {
    input: 'background.js',
    output: {
      file: 'dist/chrome/background.js',
      format: 'es'
    },
    plugins: [
      ...commonPlugins,
      copy({
        targets: [
          { src: 'manifest.chrome.json', dest: 'dist/chrome', rename: 'manifest.json' },
          // Kopiere statische Files, ignoriere falls (noch) nicht existent
          ...staticFiles.map(file => ({ src: file, dest: 'dist/chrome' }))
        ]
      })
    ]
  },
  // Firefox Build
  {
    input: 'background.js',
    output: {
      file: 'dist/firefox/background.js',
      format: 'es'
    },
    plugins: [
      ...commonPlugins,
      copy({
        targets: [
          { src: 'manifest.firefox.json', dest: 'dist/firefox', rename: 'manifest.json' },
          ...staticFiles.map(file => ({ src: file, dest: 'dist/firefox' }))
        ]
      })
    ]
  }
];
