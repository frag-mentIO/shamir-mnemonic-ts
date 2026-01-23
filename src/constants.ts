import { bitsToWords } from './utils';

export const RADIX_BITS = 10;
/** The length of the radix in bits. */

export const RADIX = 2 ** RADIX_BITS;
/** The number of words in the wordlist. */

export const ID_LENGTH_BITS = 15;
/** The length of the random identifier in bits. */

export const EXTENDABLE_FLAG_LENGTH_BITS = 1;
/** The length of the extendable backup flag in bits. */

export const ITERATION_EXP_LENGTH_BITS = 4;
/** The length of the iteration exponent in bits. */

export const ID_EXP_LENGTH_WORDS = bitsToWords(
  ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS
);
/** The length of the random identifier, extendable backup flag and iteration exponent in words. */

export const MAX_SHARE_COUNT = 16;
/** The maximum number of shares that can be created. */

export const CHECKSUM_LENGTH_WORDS = 3;
/** The length of the RS1024 checksum in words. */

export const DIGEST_LENGTH_BYTES = 4;
/** The length of the digest of the shared secret in bytes. */

export const CUSTOMIZATION_STRING_ORIG = Buffer.from('shamir', 'utf8');
/** The customization string used in the RS1024 checksum and in the PBKDF2 salt for
shares _without_ the extendable backup flag. */

export const CUSTOMIZATION_STRING_EXTENDABLE = Buffer.from('shamir_extendable', 'utf8');
/** The customization string used in the RS1024 checksum for
shares _with_ the extendable backup flag. */

export const GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
/** The length of the prefix of the mnemonic that is common to a share group. */

export const METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
/** The length of the mnemonic in words without the share value. */

export const MIN_STRENGTH_BITS = 128;
/** The minimum allowed entropy of the master secret. */

export const MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS);
/** The minimum allowed length of the mnemonic in words. */

export const BASE_ITERATION_COUNT = 10000;
/** The minimum number of iterations to use in PBKDF2. */

export const ROUND_COUNT = 4;
/** The number of rounds to use in the Feistel cipher. */

export const SECRET_INDEX = 255;
/** The index of the share containing the shared secret. */

export const DIGEST_INDEX = 254;
/** The index of the share containing the digest of the shared secret. */
