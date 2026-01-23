import * as crypto from 'crypto';
import * as shamir from '../src/index';

const MS = Buffer.from('ABCDEFGHIJKLMNOP', 'utf8');

function combinations<T>(arr: T[], k: number): T[][] {
  if (k === 0) return [[]];
  if (k > arr.length) return [];
  
  const result: T[][] = [];
  for (let i = 0; i <= arr.length - k; i++) {
    const head = arr[i];
    const tailCombos = combinations(arr.slice(i + 1), k - 1);
    for (const combo of tailCombos) {
      result.push([head, ...combo]);
    }
  }
  return result;
}

function shuffle<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

describe('Shamir Mnemonic Tests', () => {
  test('basic sharing random', () => {
    const secret = crypto.randomBytes(16);
    const mnemonics = shamir.generateMnemonics(1, [[3, 5]], secret)[0];
    const recovered1 = shamir.combineMnemonics(mnemonics.slice(0, 3));
    const recovered2 = shamir.combineMnemonics(mnemonics.slice(2));
    expect(recovered1.equals(recovered2)).toBe(true);
  });

  test('basic sharing fixed', () => {
    const mnemonics = shamir.generateMnemonics(1, [[3, 5]], MS)[0];
    expect(shamir.combineMnemonics(mnemonics.slice(0, 3)).equals(MS)).toBe(true);
    expect(shamir.combineMnemonics(mnemonics.slice(1, 4)).equals(MS)).toBe(true);
    expect(() => {
      shamir.combineMnemonics(mnemonics.slice(1, 3));
    }).toThrow(shamir.MnemonicError);
  });

  test('passphrase', () => {
    const mnemonics = shamir.generateMnemonics(1, [[3, 5]], MS, Buffer.from('TREZOR', 'utf8'))[0];
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4), Buffer.from('TREZOR', 'utf8')).equals(MS)
    ).toBe(true);
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4)).equals(MS)
    ).toBe(false);
  });

  test('non extendable', () => {
    const mnemonics = shamir.generateMnemonics(1, [[3, 5]], MS, Buffer.alloc(0), false)[0];
    expect(shamir.combineMnemonics(mnemonics.slice(1, 4)).equals(MS)).toBe(true);
  });

  test('iteration exponent', () => {
    let mnemonics = shamir.generateMnemonics(
      1,
      [[3, 5]],
      MS,
      Buffer.from('TREZOR', 'utf8'),
      true,
      1
    )[0];
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4), Buffer.from('TREZOR', 'utf8')).equals(MS)
    ).toBe(true);
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4)).equals(MS)
    ).toBe(false);

    mnemonics = shamir.generateMnemonics(
      1,
      [[3, 5]],
      MS,
      Buffer.from('TREZOR', 'utf8'),
      true,
      2
    )[0];
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4), Buffer.from('TREZOR', 'utf8')).equals(MS)
    ).toBe(true);
    expect(
      shamir.combineMnemonics(mnemonics.slice(1, 4)).equals(MS)
    ).toBe(false);
  });

  test('group sharing', () => {
    const groupThreshold = 2;
    const groupSizes = [5, 3, 5, 1];
    const memberThresholds = [3, 2, 2, 1];
    const mnemonics = shamir.generateMnemonics(
      groupThreshold,
      memberThresholds.map((t, i) => [t, groupSizes[i]] as [number, number]),
      MS
    );

    // Test all valid combinations of mnemonics.
    const groupPairs = combinations(
      mnemonics.map((m, i) => [m, memberThresholds[i]] as [string[], number]),
      groupThreshold
    );

    for (const groups of groupPairs) {
      const group1Combos = combinations(groups[0][0], groups[0][1]);
      const group2Combos = combinations(groups[1][0], groups[1][1]);
      
      for (const group1Subset of group1Combos) {
        for (const group2Subset of group2Combos) {
          const mnemonicSubset = shuffle([...group1Subset, ...group2Subset]);
          expect(shamir.combineMnemonics(mnemonicSubset).equals(MS)).toBe(true);
        }
      }
    }

    // Minimal sets of mnemonics.
    expect(
      shamir.combineMnemonics([mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]).equals(MS)
    ).toBe(true);
    expect(
      shamir.combineMnemonics([mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]).equals(MS)
    ).toBe(true);

    // One complete group and one incomplete group out of two groups required.
    expect(() => {
      shamir.combineMnemonics([...mnemonics[0].slice(2), mnemonics[1][0]]);
    }).toThrow(shamir.MnemonicError);

    // One group of two required.
    expect(() => {
      shamir.combineMnemonics(mnemonics[0].slice(1, 4));
    }).toThrow(shamir.MnemonicError);
  });

  test('group sharing threshold 1', () => {
    const groupThreshold = 1;
    const groupSizes = [5, 3, 5, 1];
    const memberThresholds = [3, 2, 2, 1];
    const mnemonics = shamir.generateMnemonics(
      groupThreshold,
      memberThresholds.map((t, i) => [t, groupSizes[i]] as [number, number]),
      MS
    );

    // Test all valid combinations of mnemonics.
    for (let i = 0; i < mnemonics.length; i++) {
      const group = mnemonics[i];
      const memberThreshold = memberThresholds[i];
      const groupCombos = combinations(group, memberThreshold);
      
      for (const groupSubset of groupCombos) {
        const mnemonicSubset = shuffle(groupSubset);
        expect(shamir.combineMnemonics(mnemonicSubset).equals(MS)).toBe(true);
      }
    }
  });

  test('all groups exist', () => {
    for (const groupThreshold of [1, 2, 5]) {
      const mnemonics = shamir.generateMnemonics(
        groupThreshold,
        [[3, 5], [1, 1], [2, 3], [2, 5], [3, 5]],
        MS
      );
      expect(mnemonics.length).toBe(5);
      expect(mnemonics.flat().length).toBe(19);
    }
  });

  test('invalid sharing', () => {
    // Short master secret.
    expect(() => {
      shamir.generateMnemonics(1, [[2, 3]], MS.slice(0, 14));
    }).toThrow();

    // Odd length master secret.
    expect(() => {
      shamir.generateMnemonics(1, [[2, 3]], Buffer.concat([MS, Buffer.from('X')]));
    }).toThrow();

    // Group threshold exceeds number of groups.
    expect(() => {
      shamir.generateMnemonics(3, [[3, 5], [2, 5]], MS);
    }).toThrow();

    // Invalid group threshold.
    expect(() => {
      shamir.generateMnemonics(0, [[3, 5], [2, 5]], MS);
    }).toThrow();

    // Member threshold exceeds number of members.
    expect(() => {
      shamir.generateMnemonics(2, [[3, 2], [2, 5]], MS);
    }).toThrow();

    // Invalid member threshold.
    expect(() => {
      shamir.generateMnemonics(2, [[0, 2], [2, 5]], MS);
    }).toThrow();

    // Group with multiple members and member threshold 1.
    expect(() => {
      shamir.generateMnemonics(2, [[3, 5], [1, 3], [2, 5]], MS);
    }).toThrow();
  });

  test('split ems', () => {
    const encryptedMasterSecret = shamir.EncryptedMasterSecret.fromMasterSecret(
      MS,
      Buffer.from('TREZOR', 'utf8'),
      42,
      true,
      1
    );
    const groupedShares = shamir.splitEms(1, [[3, 5]], encryptedMasterSecret);
    const mnemonics = groupedShares[0].map(share => share.mnemonic());

    const recovered = shamir.combineMnemonics(mnemonics.slice(0, 3), Buffer.from('TREZOR', 'utf8'));
    expect(recovered.equals(MS)).toBe(true);
  });

  test('recover ems', () => {
    const mnemonics = shamir.generateMnemonics(1, [[3, 5]], MS, Buffer.from('TREZOR', 'utf8'))[0];

    const groups = shamir.decodeMnemonics(mnemonics.slice(0, 3));
    const encryptedMasterSecret = shamir.recoverEms(groups);
    const recovered = encryptedMasterSecret.decrypt(Buffer.from('TREZOR', 'utf8'));
    expect(recovered.equals(MS)).toBe(true);
  });
});
