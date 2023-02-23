import { BufferLike, ProgressCallback, scrypt as _scrypt } from './scrypt'

export const scrypt = async (
  password: BufferLike,
  salt: BufferLike,
  N: number = 100000,
  r: number = 8,
  p: number = 1,
  derivedKeyLength: number = 64,
  progressCallback?: ProgressCallback,
) => _scrypt(crypto, password, salt, N, r, p, derivedKeyLength, progressCallback)

export { toBase64, toHex } from './scrypt'
