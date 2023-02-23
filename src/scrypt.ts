export type BufferLike = string | Buffer | ArrayBuffer | Array<number>

export type ProgressCallback = (progress: number) => boolean | void

export type SCryptInternalProgressCallback = (
  error: Error | null,
  progress: number,
  key?: Array<number>,
) => boolean | void

export const PBKDF2_HMAC_SHA256_OneIteration = async (
  crypto: Crypto,
  password: Array<number>,
  salt: Array<number>,
  derivedKeyLength: number,
): Promise<Array<number>> => {
  const masterKey = await crypto.subtle.importKey('raw', new Uint8Array(password), 'PBKDF2', false, ['deriveBits'])
  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt),
      iterations: 1,
      hash: 'SHA-256',
    },
    masterKey,
    derivedKeyLength * 8, // The key length must be specified in bits
  )
  return Array.from(new Uint8Array(derivedKey))
}

// The following is an adaptation of scryptsy
// See: https://www.npmjs.com/package/scryptsy
/**
 * The function performs a block mixing operation on BY using the Salsa20/8 stream cipher.
 * The mixing operation involves splitting the BY array into two halves, performing Salsa20/8
 * on each half using the values in x, and then interleaving the two halves back into the BY array.
 * The operation is repeated r times.
 */
export const blockMixSalsa8 = (BY: Uint32Array, Yi: number, r: number, x: Uint32Array, _X: Uint32Array) => {
  let i: number

  copyArraySubSet(BY, (2 * r - 1) * 16, _X, 0, 16)

  for (i = 0; i < 2 * r; i++) {
    blockXOR(BY, i * 16, _X, 16)
    salsa20_8(_X, x)
    copyArraySubSet(_X, 0, BY, Yi + i * 16, 16)
  }

  for (i = 0; i < r; i++) {
    copyArraySubSet(BY, Yi + i * 2 * 16, BY, i * 16, 16)
  }

  for (i = 0; i < r; i++) {
    copyArraySubSet(BY, Yi + (i * 2 + 1) * 16, BY, (i + r) * 16, 16)
  }
}

/** bitwise rotation function that performs a circular shift of
 * the 32-bit integer a to the right by b bits */
export const R = (a: number, b: number) => (a << b) | (a >>> (32 - b))

// https://cr.yp.to/salsa20.html
export const salsa20_8 = (B: Uint32Array, x: Uint32Array) => {
  copyArraySubSet(B, 0, x, 0, 16)

  for (let i = 8; i > 0; i -= 2) {
    x[4] ^= R(x[0] + x[12], 7)
    x[8] ^= R(x[4] + x[0], 9)
    x[12] ^= R(x[8] + x[4], 13)
    x[0] ^= R(x[12] + x[8], 18)
    x[9] ^= R(x[5] + x[1], 7)
    x[13] ^= R(x[9] + x[5], 9)
    x[1] ^= R(x[13] + x[9], 13)
    x[5] ^= R(x[1] + x[13], 18)
    x[14] ^= R(x[10] + x[6], 7)
    x[2] ^= R(x[14] + x[10], 9)
    x[6] ^= R(x[2] + x[14], 13)
    x[10] ^= R(x[6] + x[2], 18)
    x[3] ^= R(x[15] + x[11], 7)
    x[7] ^= R(x[3] + x[15], 9)
    x[11] ^= R(x[7] + x[3], 13)
    x[15] ^= R(x[11] + x[7], 18)
    x[1] ^= R(x[0] + x[3], 7)
    x[2] ^= R(x[1] + x[0], 9)
    x[3] ^= R(x[2] + x[1], 13)
    x[0] ^= R(x[3] + x[2], 18)
    x[6] ^= R(x[5] + x[4], 7)
    x[7] ^= R(x[6] + x[5], 9)
    x[4] ^= R(x[7] + x[6], 13)
    x[5] ^= R(x[4] + x[7], 18)
    x[11] ^= R(x[10] + x[9], 7)
    x[8] ^= R(x[11] + x[10], 9)
    x[9] ^= R(x[8] + x[11], 13)
    x[10] ^= R(x[9] + x[8], 18)
    x[12] ^= R(x[15] + x[14], 7)
    x[13] ^= R(x[12] + x[15], 9)
    x[14] ^= R(x[13] + x[12], 13)
    x[15] ^= R(x[14] + x[13], 18)
  }

  for (let i = 0; i < 16; ++i) {
    B[i] += x[i]
  }
}

// naive approach... going back to loop unrolling may yield additional performance
export const blockXOR = (S: Uint32Array, Si: number, D: Uint32Array, len: number) => {
  let i = 0
  for (const s of S.subarray(Si, Si + len)) {
    D[i++] ^= s
  }
}

export const copyArraySubSet = (
  src: Uint32Array,
  srcPos: number,
  dest: Uint32Array,
  destPos: number,
  length: number,
) => {
  dest.set(src.subarray(srcPos, srcPos + length), destPos)
}

export const isBufferLike = (o: any) => ArrayBuffer.isView(o) || Array.isArray(o)

export const ensureInteger = (value: any, name: string) => {
  if (!Number.isInteger(value)) {
    throw new Error('invalid ' + name)
  }
  return value
}

// N = Cpu cost, r = Memory cost, p = parallelization cost
// callback(error, progress, key)
export const _scrypt = async (
  crypto: Crypto,
  password: BufferLike,
  salt: BufferLike,
  N: number,
  r: number,
  p: number,
  derivedKeyLength: number,
  callback?: SCryptInternalProgressCallback,
) => {
  const MAX_VALUE = 0x7fffffff
  const BLOCK_SIZE = 128

  N = ensureInteger(N, 'N')
  r = ensureInteger(r, 'r')
  p = ensureInteger(p, 'p')

  derivedKeyLength = ensureInteger(derivedKeyLength, 'derivedKeyLength')

  if (N === 0 || (N & (N - 1)) !== 0) {
    throw new Error('N must be power of 2')
  }

  if (N > MAX_VALUE / BLOCK_SIZE / r) {
    throw new Error('N too large')
  }
  if (r > MAX_VALUE / BLOCK_SIZE / p) {
    throw new Error('r too large')
  }

  if (!isBufferLike(password)) {
    throw new Error('password must be an array or buffer')
  }
  password = Array.prototype.slice.call(password)

  if (!isBufferLike(salt)) {
    throw new Error('salt must be an array or buffer')
  }
  salt = Array.prototype.slice.call(salt)

  let b = await PBKDF2_HMAC_SHA256_OneIteration(
    crypto,
    password as Array<number>,
    salt as Array<number>,
    p * BLOCK_SIZE * r,
  )

  /**
   * The Uint32Array B is initialized with the appropriate length,
   * and then filled using a for loop that reads 4 bytes at a time
   * from the b buffer, swaps their order to little-endian,
   * and writes them into B as a single 32-bit integer.
   *
   * The resulting B buffer contains the 32-bit integer representation of b,
   * which is used as input to incrementalSMix()
   */
  const B = new Uint32Array(p * 32 * r)

  for (let i = 0; i < B.length; i++) {
    const j = i * 4
    const b0 = b[j + 0] & 0xff
    const b1 = b[j + 1] & 0xff
    const b2 = b[j + 2] & 0xff
    const b3 = b[j + 3] & 0xff
    B[i] = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
  }

  const XY = new Uint32Array(64 * r)
  const V = new Uint32Array(32 * r * N)

  const Yi = 32 * r

  // scratch space
  const x = new Uint32Array(16) // salsa20_8
  const _X = new Uint32Array(16) // blockmix_salsa8

  const totalOps = p * N * 2
  let currentOp = 0
  let lastPercent10 = null

  // Set this to true to abandon the scrypt on the next step
  let stop = false

  // State information
  let state = 0
  let i0 = 0
  let i1: number
  let Bi: number

  // How many blockmix_salsa8 can we do per step?
  const limit = callback ? Math.trunc(1000 / r) : 0xffffffff

  // This is really all I changed; making scryptsy a state machine so we occasionally
  // stop and give other evnts on the evnt loop a chance to run. ~RicMoo
  const incrementalSMix = async () => {
    if (stop) {
      return callback(new Error('cancelled'), currentOp / totalOps)
    }

    let steps: number

    switch (state) {
      case 0:
        // for (var i = 0; i < p; i++)...
        Bi = i0 * 32 * r

        copyArraySubSet(B, Bi, XY, 0, Yi) // ROMix - 1

        state = 1 // Move to ROMix 2
        i1 = 0

      // Fall through

      case 1:
        // Run up to 1000 steps of the first inner smix loop
        steps = N - i1
        if (steps > limit) {
          steps = limit
        }
        for (let i = 0; i < steps; i++) {
          // ROMix - 2
          copyArraySubSet(XY, 0, V, (i1 + i) * Yi, Yi) // ROMix - 3
          blockMixSalsa8(XY, Yi, r, x, _X) // ROMix - 4
        }

        // for (var i = 0; i < N; i++)
        i1 += steps
        currentOp += steps

        if (callback) {
          // Call the callback with the progress (optionally stopping us)
          const percent10 = Math.trunc((1000 * currentOp) / totalOps)
          if (percent10 !== lastPercent10) {
            stop = !!callback(null, currentOp / totalOps)
            if (stop) {
              break
            }
            lastPercent10 = percent10
          }
        }

        if (i1 < N) {
          break
        }

        i1 = 0 // Move to ROMix 6
        state = 2

      // Fall through

      case 2:
        // Run up to 1000 steps of the second inner smix loop
        steps = N - i1
        if (steps > limit) {
          steps = limit
        }
        for (let i = 0; i < steps; i++) {
          // ROMix - 6
          const offset = (2 * r - 1) * 16 // ROMix - 7
          const j = XY[offset] & (N - 1)
          blockXOR(V, j * Yi, XY, Yi) // ROMix - 8 (inner)
          blockMixSalsa8(XY, Yi, r, x, _X) // ROMix - 9 (outer)
        }

        // for (var i = 0; i < N; i++)...
        i1 += steps
        currentOp += steps

        // Call the callback with the progress (optionally stopping us)
        if (callback) {
          const percent10 = Math.trunc((1000 * currentOp) / totalOps)
          if (percent10 !== lastPercent10) {
            stop = !!callback(null, currentOp / totalOps)
            if (stop) {
              break
            }
            lastPercent10 = percent10
          }
        }

        if (i1 < N) {
          break
        }

        copyArraySubSet(XY, 0, B, Bi, Yi) // ROMix - 10

        // for (var i = 0; i < p; i++)...
        i0++
        if (i0 < p) {
          state = 0
          break
        }

        b = []
        for (let i = 0; i < B.length; i++) {
          b.push((B[i] >> 0) & 0xff)
          b.push((B[i] >> 8) & 0xff)
          b.push((B[i] >> 16) & 0xff)
          b.push((B[i] >> 24) & 0xff)
        }

        const derivedKey = await PBKDF2_HMAC_SHA256_OneIteration(crypto, password as Array<number>, b, derivedKeyLength)

        // Send the result to the callback
        if (callback) {
          callback(null, 1.0, derivedKey)
        }

        // Done; don't break (which would reschedule)
        return derivedKey
    }

    // Schedule the next steps
    if (callback) {
      setImmediate(incrementalSMix)
    }
  }

  // Run the smix state machine until completion
  if (!callback) {
    while (true) {
      const derivedKey = await incrementalSMix()
      if (derivedKey != undefined) {
        return derivedKey
      }
    }
  }

  // Bootstrap the async incremental smix
  await incrementalSMix()
}

export const toHex = (p: Array<number>) => {
  const enc = '0123456789abcdef'
  const len = p.length
  const hex = new Array(len * 2)

  for (let i = 0, j = 0; i < len; i++, j += 2) {
    hex[j] = enc[(p[i] >>> 4) & 15]
    hex[j + 1] = enc[p[i] & 15]
  }

  return hex.join('')
}

export const toBase64 = (p: Array<number>) => {
  const enc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const len = p.length
  const base64 = new Array(Math.ceil(len / 3) * 4)

  let i = 0
  let j = 0

  while (i < len) {
    const a = p[i++]
    const b = i < len ? p[i++] : 0
    const c = i < len ? p[i++] : 0
    const t = (a << 16) + (b << 8) + c

    base64[j++] = enc[(t >>> 18) & 63]
    base64[j++] = enc[(t >>> 12) & 63]
    base64[j++] = enc[(t >>> 6) & 63]
    base64[j++] = enc[t & 63]
  }

  const padding = len % 3
  if (padding > 0) {
    base64[base64.length - 1] = '='
    if (padding === 1) base64[base64.length - 2] = '='
  }
  return base64.join('')
}

export const scrypt = async (
  crypto: Crypto,
  password: BufferLike,
  salt: BufferLike,
  N: number = 100000,
  r: number = 8,
  p: number = 1,
  derivedKeyLength: number = 64,
  progressCallback?: ProgressCallback,
) =>
  new Promise<Uint8Array>(async (resolve, reject) => {
    let lastProgress = 0
    if (typeof progressCallback === 'function') {
      progressCallback(0)
    }
    // perform a Unicode representation normalization to not fall for differences in
    // composed/decomposed text representations -- a Unicode speciality
    if (typeof password === 'string') {
      password = Array.from(new TextEncoder().encode(password.normalize('NFKC')))
    }
    if (typeof salt === 'string') {
      salt = Array.from(new TextEncoder().encode(salt.normalize('NFKC')))
    }

    _scrypt(
      crypto,
      password,
      salt,
      N,
      r,
      p,
      derivedKeyLength,
      (error: Error | null, progress: number, key: Array<number>) => {
        if (error) {
          reject(error)
        } else if (key) {
          resolve(new Uint8Array(key))

          // calling it after the resolve enables the
          // callback to access the derivedKey in time
          if (progressCallback && lastProgress !== 1) {
            progressCallback(1)
          }
        } else if (progressCallback && progress !== lastProgress) {
          lastProgress = progress
          return progressCallback(progress)
        }
      },
    )
  })
