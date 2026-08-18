# [Open-Source Libraries] `@exodus/keystore-mobile` defaults Android secret storage to `SECURE_SOFTWARE` instead of `SECURE_HARDWARE`

**Target asset**: `github.com/ExodusOSS/hydra` (Open-Source Libraries — SDK & Crypto group)
**Weakness class**: CWE-693 (Protection Mechanism Failure) / insecure default configuration
**Suggested severity**: Low (self-assessed — see confidence notes; final call is Exodus's)

## Summary

`@exodus/keystore-mobile` (`hydra/adapters/keystore-mobile/src/index.js`), the library that wraps
`react-native-keychain` for storing secrets on mobile, defaults every Android secret write to
`SECURITY_LEVEL.SECURE_SOFTWARE`. It does not request `SECURE_HARDWARE`, and does not attempt
`SECURE_HARDWARE` with a fallback to `SECURE_SOFTWARE` only when a device lacks a hardware-backed keystore.
Any caller of this library that doesn't explicitly pass a `securityLevel` override — which is exactly the
usage pattern shown in the library's own README — gets the weaker tier.

`SECURE_HARDWARE` requires Android to generate/hold the key inside a TEE or StrongBox secure element (and
fails the call rather than silently degrade if unsupported); `SECURE_SOFTWARE` accepts a software-backed key
with no such guarantee. On devices that do support hardware-backed storage, this default means the app isn't
taking advantage of it, weakening resistance to key extraction on a compromised/rooted OS compared to what
that same device's hardware could otherwise provide.

## Affected code

`hydra/adapters/keystore-mobile/src/index.js`, lines 16–22:

```js
const defaultSetOptions = {
  accessible: reactNativeKeychain.ACCESSIBLE.WHEN_UNLOCKED,
  ...(platform === 'android'
    ? { securityLevel: reactNativeKeychain.SECURITY_LEVEL.SECURE_SOFTWARE }
    : {}),
  ...options,
}
```

`hydra/adapters/keystore-mobile/README.md` shows the documented usage with no `options` override at all:

```js
const keystore = createKeystore({ reactNativeKeychain, platform: Platform.OS })
```

## Steps to reproduce / PoC

The attached script (`poc/keystore-mobile-security-level.mjs`) re-executes the library's own default-merging
logic (copied verbatim from the file above) against a mock of the `react-native-keychain` API, and shows what
`setInternetCredentials` actually receives as `securityLevel` for a default Android write:

```bash
node poc/keystore-mobile-security-level.mjs
```

Output:
```
setInternetCredentials called with securityLevel: SECURE_SOFTWARE

Result: on Android, a caller that does not explicitly pass securityLevel gets SECURE_SOFTWARE -- NOT SECURE_HARDWARE.
```

This confirms the library's behavior directly from source; it does not require a device or the
`react-native-keychain` native module.

## Impact

Reduced hardware-backed protection for whatever secrets are stored via this library's default path, on
Android devices that do support `SECURE_HARDWARE` (StrongBox/TEE). Concretely, a device compromise that can
read software Keystore-protected material (e.g. certain root/OS-level exploits) could extract that secret,
where a `SECURE_HARDWARE`-backed key would instead have had to be used in-place by the secure element without
ever exposing raw key material to the OS.

## Confidence / honest caveats (please read before triaging)

- **I could not confirm this default is what the production mobile app actually uses.** In this public
  mirror, `keystore-mobile` is only exercised by `apps/sdk-playground` (an example app using a mocked
  keychain). The real `exodus-mobile` app is a separate, non-public repo — it's possible the call site there
  passes an explicit `securityLevel: SECURE_HARDWARE` override that isn't visible from `hydra` alone. What
  this report demonstrates with certainty is the library's own default and its documented usage pattern —
  not confirmed production behavior. I'd appreciate you confirming this either way.
- **This overlaps with your excluded threat model.** The main benefit `SECURE_HARDWARE` provides is
  resistance to a compromised/rooted device extracting key material, and your program excludes "attacks
  requiring... physical access to a user's device." A rooted/malware-compromised device isn't identical to
  physical access, but is adjacent enough that you may reasonably rate this Informational rather than a paid
  severity tier — that's your call, I'm not asking you to treat it otherwise.
- **This may be an intentional compatibility choice.** Not every Android device has a hardware-backed
  keystore; forcing `SECURE_HARDWARE` unconditionally would break secret storage on devices without one. If
  so, the concrete ask below (attempt hardware first, fall back only when unsupported) still applies and
  wouldn't break that compatibility.

## Suggested fix

Attempt `SECURE_HARDWARE` first; catch the failure and fall back to `SECURE_SOFTWARE` only on devices that
don't support it, rather than defaulting every Android write to the software tier universally. This preserves
compatibility with older/budget devices while getting hardware-backed protection everywhere it's available.

---

*Drafted for the reporter's review before submission — not yet sent to Exodus.*
