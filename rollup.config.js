import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import copy from 'rollup-plugin-copy';

const commonPlugins = [
  resolve(),
  commonjs()
];

// Dateien, die 1:1 kopiert werden sollen
const staticFiles = [
  'src/content.js',
  'src/inpage.js',
  'src/popup.html',
  'src/popup.js',
  'src/popup.css',
  'src/dialog.html',
  'src/dialog.js',
  'src/dialog.css',
  'src/icons'
];

export default [
  // Chrome Build
  {
    input: 'src/background.js',
    output: {
      file: 'dist/chrome/background.js',
      format: 'es'
    },
    plugins: [
      ...commonPlugins,
      copy({
        targets: [
          { src: 'src/manifest.chrome.json', dest: 'dist/chrome', rename: 'manifest.json' },
          // Kopiere statische Files, ignoriere falls (noch) nicht existent
          ...staticFiles.map(file => ({ src: file, dest: 'dist/chrome' }))
        ]
      })
    ]
  },
  // Firefox Build
  {
    input: 'src/background.js',
    output: {
      file: 'dist/firefox/background.js',
      format: 'es'
    },
    plugins: [
      ...commonPlugins,
      copy({
        targets: [
          { src: 'src/manifest.firefox.json', dest: 'dist/firefox', rename: 'manifest.json' },
          ...staticFiles.map(file => ({ src: file, dest: 'dist/firefox' }))
        ]
      })
    ]
  }
];