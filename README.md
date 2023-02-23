<h1 align="center">@jsheaven/scrypt</h1>

> Implements `scrypt` based on the original codebase of `scrypt-js`, but using the Web Crypto API, isomorphic, for Browsers, Node.js and shipped in all module formats

<h2 align="center">User Stories</h2>

1. As a developer, I want to use a modern `scrypt` implementation that is fast and that makes use of the Web Crypto API

<h2 align="center">Features</h2>

- ✅ Provides `scrypt` with meaningful default values
- ✅ Available as a simple API supporting UTF8 `string` input and hex/base64 key conversion
- ✅ `PBKDF2_HMAC_SHA256` implementation provided by the standard Web Crypto API
- ⚠️ ~2x slower than `scrypt-js` - this is by design (Web Crypto invocation overhead)
- ⛔ Implementation is similar to `scrypt-js` but no security audit has been done yet - mind the risk
- ✅ Just `1857 byte` nano sized (ESM, gizpped, for browsers)
- ✅ 0 dependencies
- ✅ Tree-shakable and side-effect free
- ✅ Runs on Windows, Mac, Linux, CI tested
- ✅ First class TypeScript support
- ✅ 100% Unit Test coverage

<h2 align="center">Example usage</h2>

<h3 align="center">Setup</h3>

- yarn: `yarn add @jsheaven/scrypt`
- npm: `npm install @jsheaven/scrypt`

<h3 align="center">ESM (browser)</h3>

```ts
import { scrypt, toHex, toBase64 } from '@jsheaven/scrypt/browser'

info('LONG', `N = Math.pow(2, 16), r = 8, p = 1, derivedKeyLength = 64`)

// use the derivedKey for encryption - make sure to rember the derivedKey for decryption
// and the salt to be able to re-construct the same derivedKey from the input password
// again. *Never* store the password anywhere in cleartext.
const derivedKey = await scrypt('some_password', 'some_salt', 1024, 8, 1, 64)

log('DONE', 'derivedKey (base64) length', derivedKey.length)
log('KEY', toBase64(derivedKey))

// scrypt is designed to be slow in order to be hard to attack using brute force attacks,
// therefore, you can provide a callback function to enable user-feedback (e.g. a progress bar)
import { log, info, clearPrevLine } from '@jsheaven/status-message'

info('LONG', `N = Math.pow(2, 16), r = 8, p = 1, derivedKeyLength = 64`)

const derivedKey2 = await scrypt('some_password2', 'some_salt2', Math.pow(2, 16), 8, 1, 64, (progress) => {
  clearPrevLine() // replace the last status report
  info(`GEN`, `Generating derived key (scrypt): ${Math.trunc(progress * 100)}%`)
})
log(`DONE`, 'derivedKey (key) length', derivedKey2.length)
log('KEY', toHex(derivedKey2))
```

<h3 align="center">Node.js</h3>

```ts
const { scrypt } = require('@jsheaven/scrypt/node')

// same API like the browser variant
```

<h3 align="center">CommonJS</h3>

```ts
const { scrypt } = require('...')

// same API like ESM variant
```

<h2 align="center">Advanced use-cases</h2>

See the [tests] to get an idea about advanced use-cases, such as providing password and salt using `BufferLike` data structures or cancelling the key deviation process while it is processing.

<h2 align="center">Acknowledgements</h2>

[`scrypt`](https://en.wikipedia.org/wiki/Scrypt) was created by [Colin Percival](https://en.wikipedia.org/wiki/Colin_Percival) in 2009.

This implementation is closely related to `scrypt-js`, however it has been reimplemented from
scratch and optimized quite intensively for the modern web platform. However, this library still follows the same path that [already has been paved years ago](https://github.com/ricmoo/scrypt-js).

<h2 align="center">Performance</h2>

Compared to `scrypt-js`, this library performs ~2x worse in regards to speed.
This is, because each call to the Web Crypto API comes with an invocation overhead.
Also, to keep the internal implementation of `scrypt-js` untouched, data structure conversion
between TypedArray (`Uint8Array`) and `Array<number>` needs to be done, including multiple
copying of buffers. Wether this should be changed, and optimized, is something I'm still
thinking about and where I'm hoping to receive feedback from the community.

<h3 align="center">Documentation</h3>

This library implements the scrypt key derivation function in `src/scrypt.ts`.

The function `PBKDF2_HMAC_SHA256_OneIteration` is an implementation of PBKDF2 using HMAC with SHA256 as the hash function. This function is used as part of the scrypt algorithm to derive a pseudorandom key from a password and a salt.

`_scrypt` is the main function. It takes a password and a salt, along with three parameters (N, r, and p) that control the CPU and memory cost of the algorithm, and derives a pseudorandom key of a specified length. The algorithm works by performing a series of memory-hard operations that make it difficult to perform a brute-force attack on the password. The progress of the algorithm can be monitored through a callback function.

The `blockMixSalsa8`, `salsa20_8`, and `blockXOR` functions are helper functions used by the scrypt algorithm to perform the memory-hard operations.

The `BufferLike` and `ProgressCallback` types as well as the `isBufferLike` function are utility interfaces/functions used to handle different types of input buffers and progress callbacks.
