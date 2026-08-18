# Candidate findings — needs human judgment before submitting

Unlike `CODE_REVIEW_hydra.md` (areas checked, nothing found), this file is for things that *are* concrete
and demonstrable from source, but where I'm not certain they clear the bar for a paid report — read the
caveats before submitting anything from here.

---

## 0. `@exodus/keychain@12.0.0` does not enforce its own documented seed-switch protection

**Status**: HackerOne's automated pre-submission check rejected finding #1 (below) as "Lack of SSL
Pinning"-category — a hardening issue requiring a compromised device, not directly exploitable. This finding
is different in kind: it requires no device compromise, no root, nothing beyond calling a public library
method twice — pure application-logic. Submit this one.

**File**: `github.com/ExodusOSS/hydra`, `features/keychain/module/keychain.js` (also published standalone as
`@exodus/keychain` on npm — this finding is against npm's **latest published version, 12.0.0**, installed and
executed for real, not against a stale mirror)
**PoC**: `poc/keychain-silent-seed-switch.mjs` (`npm install @exodus/keychain@12.0.0 && node
keychain-silent-seed-switch.mjs` — installs and runs the actual published package, no mocks)

### What the code does vs. what it documents

`@exodus/keychain`'s own CHANGELOG, under the v12.0.0 breaking-change entry, states:

> Unlocking a different seed without an intervening `lock()` now throws.

The actual shipped `unlock()` method does not implement this. It's wrapped in `restrictConcurrency`
(`make-concurrent`), which only serializes concurrent calls — it does not compare the seed across sequential
calls. Calling `unlock(seedA)` then `unlock(seedB)` (different seed, no `lock()` in between) does not throw:
it silently drops seed A's derived key material and replaces it with seed B's, with zero signal that a switch
happened.

### Reproduction (ran against the real package)

```
unlocked seed A, seedId: 824b7607898267b0ee177e293ba39753857e73d2
isLocked after unlock A: false
unlock(seedB) did NOT throw. seedId: c03af2465953de9a2276c0c2219be1d4b2ed6134
This contradicts the CHANGELOG-documented breaking change for v12.0.0.
seed A no longer usable after silent switch to B: seed with id "824b7607898267b0ee177e293ba39753857e73d2" is not initialized
```

### Impact and honest caveats

The documented guarantee exists specifically so that application code integrating this library can rely on
"switching which seed is active always requires an explicit `lock()` first, or it throws" as a safety net
against accidentally operating on the wrong seed (stale session state, a bug in a multi-profile/account-switch
flow, etc.). That safety net does not exist. I can't point to a specific exploited call site in the actual
Exodus apps (those callers are in private repos), so I can't prove a concrete "attacker forces this" chain —
but that's true of most missing-invariant bugs reported at the library level, and the mismatch between
documented and actual behavior is unambiguous and 100% reproducible with no special access. This is
substantially stronger footing than finding #1: no rooted/compromised device is needed anywhere in this
chain, and both the repo (`hydra`) and the npm package (`@exodus/keychain`) are named directly in the
program's scope table.

### Suggested fix

Either implement the assertion the CHANGELOG already promises (throw in `unlock()` if a different, non-external
seed is already active and `lock()` wasn't called first), or correct the CHANGELOG/README to stop claiming a
guarantee that isn't enforced — currently a consumer of this library has no way to know from the code alone
that the protection is missing.

---

## 1. `@exodus/keystore-mobile` defaults Android secret storage to `SECURE_SOFTWARE`, not `SECURE_HARDWARE`

**Status**: rejected by HackerOne's automated pre-submission check ("Lack of SSL Pinning" category — requires
a compromised/rooted device, describes hardening not a directly exploitable vulnerability). Not submitted.
Keeping the writeup below for reference.

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
