export class MnemonicError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = 'MnemonicError';
  }
}

function _roundBits(n: number, radixBits: number): number {
  /** Get the number of `radixBits`-sized digits required to store a `n`-bit value. */
  return Math.ceil(n / radixBits);
}

export function bitsToBytes(n: number): number {
  /** Round up bit count to whole bytes. */
  return _roundBits(n, 8);
}

export function bitsToWords(n: number): number {
  /** Round up bit count to a multiple of word size. */
  // Import constants here to handle circular dependency
  // This will work as long as calls to bitsToWords only happen *after* RADIX_BITS are declared
  const { RADIX_BITS } = require('./constants');
  
  if (!RADIX_BITS) {
    throw new Error('Declare RADIX_BITS *before* calling this');
  }

  return _roundBits(n, RADIX_BITS);
}

export function* intToIndices(value: number, length: number, radixBits: number): Generator<number> {
  /** Convert an integer value to indices in big endian order. */
  const mask = (1 << radixBits) - 1;
  for (let i = length - 1; i >= 0; i--) {
    yield (value >> (i * radixBits)) & mask;
  }
}

/**
 * Constant-time buffer comparison to prevent timing attacks.
 * Returns true if buffers are equal, false otherwise.
 * Always takes the same amount of time regardless of buffer contents.
 */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Still perform comparison to maintain constant time
    let dummy = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      dummy |= a[i] ^ b[i];
    }
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Creates an independent copy of a buffer (or portion of it).
 * Use this instead of .slice() when working with sensitive data.
 */
export function secureBufferCopy(
  source: Buffer,
  start: number = 0,
  end?: number
): Buffer {
  const endIndex = end !== undefined ? end : source.length;
  const length = endIndex - start;
  const copy = Buffer.allocUnsafe(length);
  source.copy(copy, 0, start, endIndex);
  return copy;
}

/**
 * Securely overwrites a buffer with zeros.
 * Note: In JavaScript, this doesn't guarantee memory is cleared
 * (due to GC), but it's a best practice.
 */
export function secureBufferFill(buffer: Buffer, value: number = 0): void {
  buffer.fill(value);
}

export type Passphrase = string | Buffer;

/**
 * Normalizes a passphrase (string or Buffer) to a Buffer for internal use.
 * - If a string is passed, it is encoded as UTF-8.
 * - If a Buffer is passed, it must contain valid UTF-8; otherwise an Error is thrown.
 * @param passphrase The passphrase as a string or UTF-8-encoded Buffer.
 * @returns The passphrase as a Buffer.
 */
export function normalizePassphrase(passphrase: Passphrase): Buffer {
  if (typeof passphrase === 'string') {
    return Buffer.from(passphrase, 'utf8');
  }
  // Buffer: verify it is valid UTF-8 (round-trip check)
  const roundTrip = Buffer.from(passphrase.toString('utf8'), 'utf8');
  if (roundTrip.compare(passphrase) !== 0) {
    throw new Error(
      'The passphrase buffer must contain valid UTF-8 when provided as a Buffer.'
    );
  }
  return passphrase;
}
