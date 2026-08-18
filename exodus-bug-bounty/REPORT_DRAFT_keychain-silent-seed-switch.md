# [Open-Source Libraries] @exodus/keychain unlock() silently switches the active seed instead of enforcing its own documented protection

## Report title
```
@exodus/keychain: unlock() silently replaces the active seed instead of throwing as documented (v12.0.0)
```

## Asset
`github.com/ExodusOSS/hydra` (also independently in scope as the published npm package `@exodus/keychain`)

## Weakness
"Improper Enforcement of Behavioral Workflow" / "Insufficient Verification of Data Authenticity" — pick
whichever is closest in the dropdown; if neither exists, "Security Misconfiguration" is an acceptable fallback.
This is not a hardening suggestion — it's a documented safety invariant that isn't enforced in code.

## Severity
Leave for Exodus to set. Self-assessed Low–Medium: no special access or device compromise required to
reproduce, but the concrete blast radius depends on internal (private-repo) callers this session can't see.

## Description field

```
## Summary:
`@exodus/keychain`'s own CHANGELOG (v12.0.0, "BREAKING CHANGES") states: "Unlocking a different seed without
an intervening `lock()` now throws." The shipped `unlock()` implementation (features/keychain/module/keychain.js
in github.com/ExodusOSS/hydra, also published standalone as @exodus/keychain on npm) does not implement this.
`unlock()` is wrapped in `restrictConcurrency` (make-concurrent), which only serializes concurrent calls to the
same function -- it does not compare the seed across sequential calls. Calling `unlock(seedA)` and then
`unlock(seedB)` (a different seed, with no `lock()` call in between) does not throw: it silently drops seed
A's derived key material from the in-memory keychain and replaces it with seed B's, with no error, warning,
or other signal that a switch occurred.

I verified this against the actual, currently-published npm package (@exodus/keychain@12.0.0) via a real
`npm install` and script execution -- not a mock or a stale checkout.

## Steps To Reproduce:
1. `npm install @exodus/keychain@12.0.0`
1. Run the attached PoC (poc/keychain-silent-seed-switch.mjs): it constructs a `Keychain` instance, calls
   `unlock(seedA)`, then calls `unlock(seedB)` (a different 64-byte seed) with no `lock()` call in between.
1. Observe the second `unlock()` call returns successfully instead of throwing, and that seed A's key
   material is now gone (`getPublicKey` for seed A's id throws "seed ... is not initialized") -- confirming
   the switch happened silently rather than being rejected.

## Supporting Material/References:
* PoC script (attached): poc/keychain-silent-seed-switch.mjs -- installs and runs the real published
  package and prints the actual (non-throwing) behavior.
* CHANGELOG entry documenting the claimed (but unenforced) guarantee: the @exodus/keychain package's own
  CHANGELOG.md, v12.0.0 entry, "BREAKING CHANGES" section.
* Affected code: features/keychain/module/keychain.js, `unlock()` method.

I don't have visibility into the actual Exodus mobile/desktop app call sites (private repos), so I can't
point to a specific place this gets triggered by end-user-reachable input today. What I can show conclusively
is that the documented safety net -- meant to catch exactly this class of "wrong seed became active" bug --
does not exist in the shipped library, so any internal caller that (correctly, per your own docs) assumes
switching seeds without `lock()` is rejected is not actually protected.
```

## Impact field

```
## Summary:
This removes a documented safety invariant meant to prevent an application from silently operating against
the wrong seed. Any internal flow that unlocks a new seed without an intervening `lock()` -- whether by bug,
race, or an incomplete account-switch/profile-switch implementation -- succeeds silently instead of failing
loudly as the library's own changelog promises. The most direct consequence demonstrated here is silent loss
of access to the previously active seed's derived keys mid-session with no error surfaced to the caller;
depending on what a specific internal caller assumes about this guarantee, the practical severity could range
from a confusing UX bug to signing/derivation happening against an unexpected seed without any safeguard
catching it.

Suggested fix: implement the assertion the CHANGELOG already documents (throw in `unlock()` when a different,
already-active non-external seed exists and `lock()` was not called first), or correct the CHANGELOG/README
to accurately reflect that this protection isn't present.
```

## Attachment to upload
`poc/keychain-silent-seed-switch.mjs`
