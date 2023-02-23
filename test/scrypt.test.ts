import { jest } from '@jest/globals'
import { scrypt, PBKDF2_HMAC_SHA256_OneIteration, salsa20_8, R, ensureInteger, _scrypt } from '../dist/scrypt.esm'
import {
  PBKDF2_HMAC_SHA256_OneIterationTestFixtureInput,
  PBKDF2_HMAC_SHA256_OneIterationTestFixtureResult,
  testVectors,
} from './inputs'
import { info } from '@jsheaven/status-message'

let cryptoApi: Crypto
export const getCryptoApi = async (): Promise<Crypto> => {
  if (typeof window === 'undefined') {
    if (!cryptoApi) {
      const { webcrypto } = await import('crypto')
      cryptoApi = webcrypto as Crypto
    }
    return cryptoApi
  } else {
    return window.crypto
  }
}

describe('R', () => {
  it('performs a circular shift of the 32-bit integer to the right by b bits', () => {
    expect(R(0x00000001, 0)).toBe(0x00000001)
    expect(R(0x00000001, 1)).toBe(0x00000002)
    expect(R(0x00000001, 2)).toBe(0x00000004)
    expect(R(0x00000001, 3)).toBe(0x00000008)
    expect(R(0x00000001, 4)).toBe(0x00000010)
    expect(R(0x00000001, 5)).toBe(0x00000020)
    expect(R(0x00000001, 6)).toBe(0x00000040)
    expect(R(0x00000001, 7)).toBe(0x00000080)
    expect(R(0x00000001, 8)).toBe(0x00000100)
    expect(R(0x00000001, 9)).toBe(0x00000200)
    expect(R(0x00000001, 10)).toBe(0x00000400)
    expect(R(0x00000001, 11)).toBe(0x00000800)
    expect(R(0x00000001, 12)).toBe(0x00001000)
    expect(R(0x00000001, 13)).toBe(0x00002000)
    expect(R(0x00000001, 14)).toBe(0x00004000)
    expect(R(0x00000001, 15)).toBe(0x00008000)
    expect(R(0x00000001, 16)).toBe(0x00010000)
  })
})
describe('ensureInteger', () => {
  it('returns value if it is an integer', () => {
    expect(ensureInteger(42, 'value')).toBe(42)
  })

  it('throws an error if value is not an integer', () => {
    expect(() => {
      ensureInteger('42', 'value')
    }).toThrowError('invalid value')
  })
})

describe('PBKDF2_HMAC_SHA256_OneIteration', () => {
  it('should derive a key from input', async () => {
    const derviedKey = await PBKDF2_HMAC_SHA256_OneIteration(
      await getCryptoApi(),
      PBKDF2_HMAC_SHA256_OneIterationTestFixtureInput.password,
      PBKDF2_HMAC_SHA256_OneIterationTestFixtureInput.salt,
      PBKDF2_HMAC_SHA256_OneIterationTestFixtureInput.derivedKeyLength,
    )

    // weak test but it is about correctness of impl.
    expect(derviedKey).toEqual(PBKDF2_HMAC_SHA256_OneIterationTestFixtureResult)
  })
})

describe('salsa20_8', () => {
  it('should properly encrypt given input and key', () => {
    const input = new Uint32Array([
      0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210, 0xf0e1d2c3, 0x4d3b2a19, 0x88776655, 0xccbbaa99, 0xffeeddcc,
      0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
    ])
    const key = new Uint32Array([
      0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001,
      0x09000000, 0x4a000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    ])
    const expectedOutput = new Uint32Array([
      1250799268, 4087582148, 2945756976, 3733341917, 2659195797, 2553566787, 2328477867, 203991664, 1575825206,
      772941183, 3345063505, 3852118495, 161841683, 140748184, 4207948587, 2978849380,
    ])
    salsa20_8(input, key)
    expect(input).toEqual(expectedOutput)
  })

  it('generates expected output for input of all zeroes', () => {
    const input = new Uint32Array(16)
    const output = new Uint32Array(16)
    salsa20_8(output, input)
    expect(output).toEqual(new Uint32Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
  })

  it('generates expected output for input with 1 bit set', () => {
    const input = new Uint32Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    const output = new Uint32Array(16)
    salsa20_8(output, input)
    expect(output).toEqual(new Uint32Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
  })

  it('throws out of bounds for when there are too much entries', () => {
    const input = new Uint32Array(([] as Array<number>).fill(1, 0, 16))
    const output = new Uint32Array(16)
    try {
      salsa20_8(output, input)
      expect(output).toEqual(new Uint32Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    } catch (e) {
      expect(e.message).toEqual('offset is out of bounds')
    }
  })
})

describe('_scrypt', () => {
  it('throws an error if N is not a power of 2', async () => {
    await expect(
      _scrypt(await getCryptoApi(), Buffer.from('password'), Buffer.from('salt'), 3, 16, 1, 32),
    ).rejects.toThrow('N must be power of 2')
  })

  it('throws an error if N is too large', async () => {
    await expect(
      _scrypt(await getCryptoApi(), Buffer.from('password'), Buffer.from('salt'), 1 << 30, 16, 1, 32),
    ).rejects.toThrow('N too large')
  })

  it('throws an error if r is too large', async () => {
    const password = Buffer.from('password')
    const salt = Buffer.from('salt')
    const N = 1024
    const r = 10000
    const p = 10000
    const derivedKeyLength = 32

    await expect(_scrypt(await getCryptoApi(), password, salt, N, r, p, derivedKeyLength)).rejects.toThrowError(
      'r too large',
    )
  })

  it('throws an error if password is not a buffer', async () => {
    await expect(
      _scrypt(await getCryptoApi(), 'password' as any, Buffer.from('salt'), 1 << 14, 16, 1, 32),
    ).rejects.toThrow('password must be an array or buffer')
  })

  it('throws an error if salt is not a buffer', async () => {
    await expect(
      _scrypt(await getCryptoApi(), Buffer.from('password'), 'salt' as any, 1 << 14, 16, 1, 32),
    ).rejects.toThrow('salt must be an array or buffer')
  })

  it('scrypt stops execution when the callback returns true', async () => {
    const mockedCallback = jest.fn((error, progress: number) => {
      if (progress >= 1) {
        // Stop execution after 100 steps
        return true
      }
      return false
    })

    const password = Buffer.from('password')
    const salt = Buffer.from('salt')
    const N = 1024
    const r = 8
    const p = 1
    const derivedKeyLength = 32

    try {
      _scrypt(await getCryptoApi(), password, salt, N, r, p, derivedKeyLength, mockedCallback)
    } catch (e) {
      expect(e.message).toEqual('cancelled')
    }
  })

  it('should run until completion', async () => {
    const password = Buffer.from('password')
    const salt = Buffer.from('salt')
    const N = 1024
    const r = 8
    const p = 1
    const derivedKeyLength = 64

    const result = await _scrypt(await getCryptoApi(), password, salt, N, r, p, derivedKeyLength)

    expect(result).toBeDefined()
    expect(result).toBeInstanceOf(Array)
    expect(result).toHaveLength(derivedKeyLength)
  })

  it('calls progressCallback with 1 if it exists and lastProgress is not 1', async () => {
    const password = Buffer.from('paassss', 'hex')
    const salt = Buffer.from('salty', 'utf8')

    // Define a mock function for the progressCallback
    const mockProgressCallback = jest.fn(() => {})

    // Call the function with a truthy progressCallback and lastProgress not equal to 1
    await scrypt(await getCryptoApi(), password, salt, 16, 8, 1, 64, mockProgressCallback)

    // Verify that the progressCallback was called with 1
    expect(mockProgressCallback).toHaveBeenCalledWith(1)
  })

  it('normalize password if it is a string', async () => {
    const password = 'pàsswörd'
    const key = await scrypt(await getCryptoApi(), password, Buffer.from('salty', 'utf8'), 1024, 8, 1, 64)

    expect(key).toBeDefined()
    expect(key).toBeInstanceOf(Uint8Array)
  })

  it('normalize salt if it is a string', async () => {
    const password = 'pàsswörd'
    const salt = '𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡'
    const key = await scrypt(await getCryptoApi(), password, salt, 1024, 8, 1, 64)

    expect(key).toBeDefined()
    expect(key).toBeInstanceOf(Uint8Array)
  })
})

describe('scrypt', () => {
  for (let i = 0; i < testVectors.length; i++) {
    const test = testVectors[i]

    const password = Buffer.from(test.password, 'hex')
    const salt = Buffer.from(test.salt as string, 'hex')
    const N = test.N
    const p = test.p
    const r = test.r
    const dkLen = test.dkLen
    const derivedKeyHex = test.derivedKey

    it('Test ' + String(i), async () => {
      try {
        let lastPct: string
        const key = await scrypt(await getCryptoApi(), password, salt, N, r, p, dkLen, (pct) => {
          const formattedPct = Math.trunc(pct * 100).toString()

          if (formattedPct !== lastPct && formattedPct.endsWith('0')) {
            lastPct = formattedPct

            if (formattedPct.endsWith('0')) {
              info(`Test ${i}: ${formattedPct}%`)
            }
          }
        })

        expect(Buffer.from(key).toString('hex')).toEqual(derivedKeyHex)
      } catch (e) {
        console.log(e)
        expect(true).toBe(false)
      }
    })
  }

  it('Test cancelling', async () => {
    try {
      await scrypt(await getCryptoApi(), [1, 2], [1, 2], 1 << 10, 8, 1, 32, (percent: number) => {
        // >= 50%
        if (percent >= 0.5) {
          return true // causes a cancellation when true is returned
        }
      })
    } catch (e) {
      expect(e.message).toEqual('cancelled')
    }
  })
})
