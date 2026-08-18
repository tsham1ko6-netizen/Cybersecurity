# Ready-to-paste text for the HackerOne report form (Report Intent #277140)

## Asset
`github.com/ExodusOSS/hydra`

## Weakness
Closest fits, pick whichever your dropdown offers (in order of preference):
- "Insecure Storage of Sensitive Information"
- "Cryptographic Issues"
- "Security Misconfiguration" (fallback if neither above exists)

## Severity
Leave as **Low** or **Informational** if the dropdown lets you self-assess — don't pick anything higher,
the report itself asks Exodus to make the real call and oversetting it hurts credibility.

## Description field — paste this over the template

```
## Summary:
`@exodus/keystore-mobile` (hydra/adapters/keystore-mobile/src/index.js, lines 16-22), the library that
wraps react-native-keychain for storing secrets on mobile, defaults every Android secret write to
SECURITY_LEVEL.SECURE_SOFTWARE instead of SECURE_HARDWARE, and does not attempt SECURE_HARDWARE with a
fallback -- unless the caller explicitly overrides `securityLevel`, which is not what the library's own
README shows as the documented usage. On devices that do support a hardware-backed keystore (TEE/StrongBox),
this means secrets stored via the documented default path don't get that stronger, hardware-isolated
protection.

**Note on PoC format**: this is a static-analysis finding against a configuration default in open-source
code, not a live, video-recordable attack against a running app/service -- there's no UI flow or network
request to capture on video. The runnable PoC below reproduces the actual finding directly against the
library's own logic; I'm submitting it in that form rather than forcing an unrelated video. Happy to provide
whatever additional format helps triage if this isn't sufficient.

## Steps To Reproduce:
1. Clone github.com/ExodusOSS/hydra and open adapters/keystore-mobile/src/index.js, lines 16-22.
1. Observe that `defaultSetOptions.securityLevel` is set to `SECURE_SOFTWARE` for `platform === 'android'`
   with no attempt at `SECURE_HARDWARE` first.
1. Run the attached PoC script (poc/keystore-mobile-security-level.mjs), which re-executes this exact
   logic against a minimal mock of the react-native-keychain API and prints the resulting securityLevel
   for a default (no-override) Android secret write: `node poc/keystore-mobile-security-level.mjs`
1. Confirm the README's documented usage example passes no `options`, so this default is what a caller
   following the docs actually gets.

## Supporting Material/References:
* PoC script (attached): poc/keystore-mobile-security-level.mjs -- demonstrates the default securityLevel
  resolves to SECURE_SOFTWARE with no override, using the library's own merge logic.
* Affected file: hydra/adapters/keystore-mobile/src/index.js, lines 16-22
* Documented usage showing no override: hydra/adapters/keystore-mobile/README.md

I could not confirm from this public repo alone whether exodus-mobile (private, not in this mirror)
overrides this default at its call site -- if it does, this report is moot and I'd appreciate you saying so
either way.
```

## Impact field

```
## Summary:
Reduced hardware-backed protection for secrets stored via this library's default (documented) usage path,
on Android devices that do support SECURE_HARDWARE. A device compromise able to read software
Keystore-protected material could extract such a secret, where a SECURE_HARDWARE-backed key would instead
require operating in-place inside the secure element without ever exposing raw key material to the OS.

This overlaps with attacks requiring a compromised/rooted device, which is adjacent to (though not
identical to) the program's excluded "physical access" category -- I'm flagging that overlap myself rather
than letting triage discover it, since it's the main factor that should drive final severity here.

Suggested fix: attempt SECURE_HARDWARE first, catch failure, and fall back to SECURE_SOFTWARE only on
devices that don't support hardware-backed storage, instead of defaulting to the software tier universally.
```

## Attachment to upload
Upload `poc/keystore-mobile-security-level.mjs` as a file attachment on the report.
