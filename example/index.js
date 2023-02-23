import { scrypt, toHex, toBase64 } from '../dist/node/index.esm.js'

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
