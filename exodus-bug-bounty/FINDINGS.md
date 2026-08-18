# Candidate findings — needs human judgment before submitting

Unlike `CODE_REVIEW_hydra.md` (areas checked, nothing found), this file is for things that *are* concrete
and demonstrable from source, but where I'm not certain they clear the bar for a paid report — read the
caveats before submitting anything from here.

---

## 1. `@exodus/keystore-mobile` defaults Android secret storage to `SECURE_SOFTWARE`, not `SECURE_HARDWARE`

**File**: `hydra/adapters/keystore-mobile/src/index.js`, lines 16–22
**Repo**: `github.com/ExodusOSS/hydra` (explicitly in scope)
**PoC**: `poc/keystore-mobile-security-level.mjs` (runnable, `node poc/keystore-mobile-security-level.mjs`)

### What the code does

```js
const defaultSetOptions = {
  accessible: reactNativeKeychain.ACCESSIBLE.WHEN_UNLOCKED,
  ...(platform === 'android'
    ? { securityLevel: reactNativeKeychain.SECURITY_LEVEL.SECURE_SOFTWARE }
    : {}),
  ...options,
}
```

`@exodus/keystore-mobile` — described in its own `package.json` as "Secure key-value storage implementation
for secrets management" — is a thin wrapper over `react-native-keychain`. On Android, unless the caller
explicitly overrides `securityLevel` in the per-call `opts`, every secret written through `setSecret()`
requests `SECURITY_LEVEL.SECURE_SOFTWARE` rather than `SECURE_HARDWARE`. The library's own README shows the
canonical usage with **no** `options` passed at all, so the documented, "correct" way to use this library
resolves to the weaker tier.

`react-native-keychain`'s `SECURE_SOFTWARE` tells Android Keystore that a software-backed key is acceptable;
`SECURE_HARDWARE` requires the key to be generated/held inside a TEE or StrongBox secure element and makes the
call fail rather than silently fall back. Requesting only `SECURE_SOFTWARE` means the app doesn't take
advantage of hardware-isolated key storage even on devices that support it — weakening resistance to key
extraction on a compromised/rooted OS, compared to what the same device's hardware could otherwise provide.

### Why this needs judgment before submitting, not just forwarding as-is

- **I could not confirm this is what production actually ships.** This default is only exercised in this
  public mirror by `apps/sdk-playground` (an example app using a mock keychain) — the real Exodus mobile app
  (`exodus-mobile`) is a separate, private repo not in this session's scope, and it's possible the production
  wiring passes an explicit `options.securityLevel` override at the call site that isn't visible here. What
  *is* demonstrable from this repo alone is the library's default behavior and its documented usage pattern.
- **The threat model this weakens is largely what the program excludes.** The main benefit of `SECURE_HARDWARE`
  is resistance to a *compromised or rooted device* extracting key material — and the program's out-of-scope
  list explicitly excludes "attacks requiring... physical access to a user's device," which a rooted/malware-
  compromised device is adjacent to (arguably not identical, but close enough that Exodus may rule it low
  severity or N/A on that basis alone).
- **It may be an intentional compatibility tradeoff.** Not all Android devices support `SECURE_HARDWARE`
  (older devices, budget devices without a TEE/StrongBox); forcing it could break secret storage entirely on
  those devices. A stronger, still-correct version of this finding would request the library *try*
  `SECURE_HARDWARE` first and fall back to `SECURE_SOFTWARE` only when unsupported, rather than defaulting to
  the weaker tier universally — that's the actual, actionable ask if you report it.

### Suggested framing if you do submit it

Report it as a hardening gap in the *library default*, not as "private keys are extractable" — the PoC only
proves what security tier gets requested, not that a specific secret (seed, PIN, etc.) is actually routed
through this library in the shipped mobile app with no override, since that wiring lives outside this repo's
scope. Ask Exodus to confirm/deny in their response; that answer determines real severity far more than
anything further I can extract from source alone.

---

## 2. `swallowDecryptionErrors` defaults to `true` in the browser extension's encrypted storage

**Files**: `hydra/adapters/storage-encrypted/src/storage.ts` (the mechanism),
`hydra/libraries/browser-extension-adapters/encrypted-storage/encrypted-storage.js` line 7 (where the default
lives)

`createEncryptedStorage` in the browser-extension adapter defaults `swallowDecryptionErrors: true`. When a
stored value fails to decrypt (wrong key, corruption, tampering), `transformOnRead` catches it, logs a
`console.warn`, and returns `undefined` — the caller can't distinguish "never set" from "present but
undecryptable" unless it inspects logs.

Traced what's actually encrypted this way: `sdks/headless/src/unlock-encrypted-storage.js` shows the
encryption key for this store is itself derived from the wallet seed via `cachedSodiumEncryptor` under
`EXODUS_KEY_IDS.WALLET_INFO` — i.e. this store holds wallet-info-derived metadata, **not** the raw seed
(the seed lives in a different, secure-container-based store). That significantly caps the impact: worst
case here is silently-lost app metadata/settings, not silent loss of key material or a signing bypass.

**Verdict: not worth submitting on its own.** Noting it here in case it becomes relevant context alongside a
different finding, but by itself the blast radius (non-seed metadata, and it requires the attacker to already
have local write access to tamper with the ciphertext, which is out-of-scope per the program's "physical
access" exclusion) doesn't clear the bar.
