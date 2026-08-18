import { Keychain } from '@exodus/keychain'

const keychain = new Keychain({})

// Two distinct, valid 64-byte seeds (as produced by bip39.mnemonicToSeed)
const seedA = new Uint8Array(64).fill(0xaa)
const seedB = new Uint8Array(64).fill(0xbb)

const seedIdA = await keychain.unlock(seedA)
console.log('unlocked seed A, seedId:', seedIdA)
console.log('isLocked after unlock A:', await keychain.arePrivateKeysLocked())

// Per the @exodus/keychain@12.0.0 CHANGELOG:
// "Unlocking a different seed without an intervening lock() now throws."
// No lock() call here -- attempting to unlock a second, different seed directly.
let threw = false
let seedIdB
try {
  seedIdB = await keychain.unlock(seedB)
} catch (err) {
  threw = true
  console.log('unlock(seedB) threw as documented:', err.message)
}

if (!threw) {
  console.log('unlock(seedB) did NOT throw. seedId:', seedIdB)
  console.log('This contradicts the CHANGELOG-documented breaking change for v12.0.0.')

  // Show that seed A's keys are now gone -- silently swapped, not rejected.
  const pubKeyId = {
    derivationAlgorithm: 'BIP32',
    keyType: 'secp256k1',
    derivationPath: "m/44'/0'/0'/0/0",
  }
  try {
    await keychain.getPublicKey({ seedId: seedIdA, keyId: pubKeyId })
    console.log('seed A still usable after silent switch (unexpected)')
  } catch (err) {
    console.log('seed A no longer usable after silent switch to B:', err.message)
  }
}
