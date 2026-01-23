import * as crypto from 'crypto';
import {
  BASE_ITERATION_COUNT,
  CUSTOMIZATION_STRING_ORIG,
  ID_LENGTH_BITS,
  ROUND_COUNT,
} from './constants';
import { bitsToBytes } from './utils';

function _xor(a: Buffer, b: Buffer): Buffer {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

function _roundFunction(
  i: number,
  passphrase: Buffer,
  e: number,
  salt: Buffer,
  r: Buffer
): Buffer {
  /** The round function used internally by the Feistel cipher. */
  return crypto.pbkdf2Sync(
    Buffer.concat([Buffer.from([i]), passphrase]),
    Buffer.concat([salt, r]),
    (BASE_ITERATION_COUNT << e) / ROUND_COUNT,
    r.length,
    'sha256'
  );
}

function _getSalt(identifier: number, extendable: boolean): Buffer {
  if (extendable) {
    return Buffer.alloc(0);
  }
  const identifierLen = bitsToBytes(ID_LENGTH_BITS);
  const identifierBuf = Buffer.allocUnsafe(identifierLen);
  identifierBuf.writeUIntBE(identifier, 0, identifierLen);
  return Buffer.concat([CUSTOMIZATION_STRING_ORIG, identifierBuf]);
}

export function encrypt(
  masterSecret: Buffer,
  passphrase: Buffer,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Buffer {
  if (masterSecret.length % 2 !== 0) {
    throw new Error(
      'The length of the master secret in bytes must be an even number.'
    );
  }

  let l: Buffer = masterSecret.slice(0, masterSecret.length / 2);
  let r: Buffer = masterSecret.slice(masterSecret.length / 2);
  const salt = _getSalt(identifier, extendable);

  for (let i = 0; i < ROUND_COUNT; i++) {
    const f = _roundFunction(i, passphrase, iterationExponent, salt, r);
    const temp = l;
    l = r;
    r = _xor(temp, f);
  }

  return Buffer.concat([r, l]);
}

export function decrypt(
  encryptedMasterSecret: Buffer,
  passphrase: Buffer,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Buffer {
  if (encryptedMasterSecret.length % 2 !== 0) {
    throw new Error(
      'The length of the encrypted master secret in bytes must be an even number.'
    );
  }

  let l: Buffer = encryptedMasterSecret.slice(0, encryptedMasterSecret.length / 2);
  let r: Buffer = encryptedMasterSecret.slice(encryptedMasterSecret.length / 2);
  const salt = _getSalt(identifier, extendable);

  for (let i = ROUND_COUNT - 1; i >= 0; i--) {
    const f = _roundFunction(i, passphrase, iterationExponent, salt, r);
    const temp = l;
    l = r;
    r = _xor(temp, f);
  }

  return Buffer.concat([r, l]);
}
