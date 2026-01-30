import * as fs from 'fs';
import * as path from 'path';
import * as shamir from '../src/index';

type TestVector = [string, string[], string, string];

describe('Test Vectors', () => {
  const vectorsPath = path.join(__dirname, 'vectors.json');
  const vectors: TestVector[] = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

  for (const [description, mnemonics, secretHex, xprv] of vectors) {
    test(description, () => {
      if (secretHex) {
        const secret = Buffer.from(secretHex, 'hex');
        const recovered = shamir.combineMnemonics(mnemonics, 'TREZOR');
        expect(recovered.equals(secret)).toBe(true);
        
        // Note: BIP32 xprv validation would require bip32utils equivalent
        // For now, we just verify the secret matches
      } else {
        // This test vector should raise an error
        expect(() => {
          shamir.combineMnemonics(mnemonics);
        }).toThrow(shamir.MnemonicError);
      }
    });
  }
});
