// PoC: @exodus/keystore-mobile (ExodusOSS/hydra, adapters/keystore-mobile) defaults Android secret
// storage to SECURITY_LEVEL.SECURE_SOFTWARE instead of SECURE_HARDWARE when the caller does not
// explicitly override it via `options`.
//
// This directly re-implements the module's logic (copied unmodified from
// adapters/keystore-mobile/src/index.js lines 16-22) against a minimal mock of the
// `react-native-keychain` SECURITY_LEVEL enum, and shows what `setInternetCredentials`
// actually receives as its security level for an Android secret write when the caller
// passes no per-call `opts` override.

const reactNativeKeychain = {
  ACCESSIBLE: { WHEN_UNLOCKED: 'WHEN_UNLOCKED' },
  SECURITY_LEVEL: { SECURE_SOFTWARE: 'SECURE_SOFTWARE', SECURE_HARDWARE: 'SECURE_HARDWARE' },
  setInternetCredentials: async (key, _unused, _value, opts) => {
    console.log('setInternetCredentials called with securityLevel:', opts.securityLevel)
    return opts
  },
}

// --- verbatim logic from adapters/keystore-mobile/src/index.js ---
const platform = 'android'
const options = {} // <- caller passes nothing, e.g. `keystore.setSecret('seedEncryptionKey', value)`
const defaultSetOptions = {
  accessible: reactNativeKeychain.ACCESSIBLE.WHEN_UNLOCKED,
  ...(platform === 'android'
    ? { securityLevel: reactNativeKeychain.SECURITY_LEVEL.SECURE_SOFTWARE }
    : {}),
  ...options,
}
// --- end verbatim logic ---

await reactNativeKeychain.setInternetCredentials('someSensitiveKey', 'unused', '{"secret":"..."}', {
  ...defaultSetOptions,
})

console.log('\nResult: on Android, a caller that does not explicitly pass securityLevel gets',
  defaultSetOptions.securityLevel,
  '-- NOT SECURE_HARDWARE.')
