import { buildForNode, buildForBrowser } from '@jsheaven/easybuild'

await buildForNode({
  entryPoint: './src/scrypt.ts',
  outfile: './dist/scrypt.js',
  debug: process.argv.indexOf('--dev') > -1,
  esBuildOptions: {
    logLevel: 'error',
  },
})

await buildForNode({
  entryPoint: './src/index.node.ts',
  outfile: './dist/node/index.js',
  debug: process.argv.indexOf('--dev') > -1,
  esBuildOptions: {
    logLevel: 'error',
  },
})

await buildForBrowser({
  entryPoint: './src/index.browser.ts',
  outfile: './dist/browser/index.js',
  debug: process.argv.indexOf('--dev') > -1,
  esBuildOptions: {
    logLevel: 'error',
  },
})
