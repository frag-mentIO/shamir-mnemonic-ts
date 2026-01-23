# Shamir Mnemonic TypeScript

TypeScript implementation of SLIP-0039 Shamir Secret Sharing for mnemonic seed phrases.

This is a complete conversion of the Python `python-shamir-mnemonic` reference implementation to TypeScript for Node.js.

## Installation

### From npm (for users)

```bash
npm install shamir-mnemonic-ts
```

### Development setup

```bash
npm install
```

## Building

```bash
npm run build
```

## Testing

```bash
npm test
npm run test:vectors
```

## Usage

```typescript
import * as shamir from 'shamir-mnemonic-ts';

// Generate mnemonic shares
const masterSecret = Buffer.from('your-secret-here');
const mnemonics = shamir.generateMnemonics(
  1,                    // group threshold
  [[3, 5]],            // (member threshold, member count) for each group
  masterSecret,
  Buffer.from('passphrase', 'utf8')
);

// Recover master secret
const recovered = shamir.combineMnemonics(
  mnemonics[0].slice(0, 3),  // any 3 of 5 shares
  Buffer.from('passphrase', 'utf8')
);
```

## Structure

- `src/constants.ts` - SLIP-0039 constants
- `src/utils.ts` - Utility functions and error classes
- `src/wordlist.ts` - Wordlist management
- `src/rs1024.ts` - RS1024 checksum implementation
- `src/cipher.ts` - Feistel cipher for encryption/decryption
- `src/share.ts` - Share encoding/decoding
- `src/shamir.ts` - Core Shamir secret sharing algorithms
- `src/recovery.ts` - Interactive recovery state management
- `src/index.ts` - Public API exports

## Compatibility

This implementation is binary-compatible with the SLIP-0039 standard and produces/consumes the standard mnemonic format.

## License

MIT
