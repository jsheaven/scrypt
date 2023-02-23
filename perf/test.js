import { perf } from '@jsheaven/perf'
import * as scryptJsImported from 'scrypt-js'
import { scrypt } from '../dist/node/index.esm.js'

const { scrypt: scryptJs } = scryptJsImported.default

const scryptJsAlgo = {
  name: 'scrypt-js',
  fn: async (size) => {
    const password = Buffer.from('password')
    const salt = Buffer.from('salt')
    const N = Math.pow(2, size)
    const r = 8
    const p = 1
    const derivedKeyLength = 64

    await scryptJs(password, salt, N, r, p, derivedKeyLength)
  },
}

const scryptAlgo = {
  name: 'scrypt',
  fn: async (size) => {
    const password = Buffer.from('password')
    const salt = Buffer.from('salt')
    const N = Math.pow(2, size)
    const r = 8
    const p = 1
    const derivedKeyLength = 64

    await scrypt(password, salt, N, r, p, derivedKeyLength)
  },
}

const measurement = await perf([scryptJsAlgo, scryptAlgo], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

console.log('measurement scrypt-js', measurement['scrypt-js'])
console.log('measurement scrypt', measurement['scrypt'])
