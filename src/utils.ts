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
