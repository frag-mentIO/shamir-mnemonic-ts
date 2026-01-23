import { CHECKSUM_LENGTH_WORDS } from './constants';

export { CHECKSUM_LENGTH_WORDS };

function _polymod(values: Iterable<number>): number {
  const GEN = [
    0xE0E040,
    0x1C1C080,
    0x3838100,
    0x7070200,
    0xE0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x3F3F120,
  ];

  let chk = 1;
  for (const v of values) {
    const b = chk >> 20;
    chk = ((chk & 0xFFFFF) << 10) ^ v;
    for (let i = 0; i < 10; i++) {
      if ((b >> i) & 1) {
        chk ^= GEN[i];
      }
    }
  }
  return chk;
}

export function createChecksum(data: Iterable<number>, customizationString: Buffer): number[] {
  const values: number[] = [
    ...Array.from(customizationString),
    ...Array.from(data),
    ...Array(CHECKSUM_LENGTH_WORDS).fill(0),
  ];
  const polymod = _polymod(values) ^ 1;
  const checksum: number[] = [];
  for (let i = CHECKSUM_LENGTH_WORDS - 1; i >= 0; i--) {
    checksum.push((polymod >> (10 * i)) & 1023);
  }
  return checksum;
}

export function verifyChecksum(data: Iterable<number>, customizationString: Buffer): boolean {
  const values = [...Array.from(customizationString), ...Array.from(data)];
  return _polymod(values) === 1;
}
