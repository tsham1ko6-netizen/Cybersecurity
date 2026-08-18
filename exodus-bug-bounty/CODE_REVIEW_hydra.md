# Static code review — ExodusOSS open-source repos

In-scope repos cloned read-only and reviewed: `github.com/ExodusOSS/crypto`, `github.com/ExodusOSS/bytes`,
`github.com/ExodusOSS/hydra` (partial — it's a very large monorepo: ~70 libraries, ~50 features, several adapters).
This is a snapshot of what's been checked so far, not a finished audit.

## Reviewed, no findings

**`crypto` repo** — `randomBytes.*`, `randomUUID.*`, `hmac.*`, `hash.*`, `utils/assert*.js`, `utils/output.js`
All platforms (node/browser/native) correctly delegate to a CSPRNG (`crypto.getRandomValues` /
`crypto.randomBytes` / Web Crypto) — no `Math.random()` fallback anywhere. UUIDv4 sets version/variant bits
correctly. `assertSize` rejects non-positive/unsafe integers. HMAC/hash type allowlists are closed sets, no
type-confusion path found.

**`bytes` repo** — `base58.js`, `fallback/base58check.js`, `wif.js`
WIF encode/decode round-trips version byte + compression flag correctly, copies (not aliases) the private
key slice. Base58check checksum comparison (`assertChecksum`) uses branchless XOR/OR across 4 bytes — that's
fine even though it's a public checksum, not a secret MAC, so timing isn't actually sensitive here anyway.

**`hydra/libraries/secure-container`** — the wallet's on-disk encrypted-file format (`crypto.js`, `index.js`,
`header.js`, `file.js`, `metadata.js`, `blob.js`)
- Passphrase → key: scrypt (N=16384, r=8, p=1, 32-byte salt) → AES-256-GCM. Standard, reasonable parameters.
- `blobKey` (the key that actually encrypts wallet data) is itself AES-GCM-encrypted under the passphrase-derived
  key, so tampering with the stored `scrypt` cost parameters (n/r/p) or salt in `metadata` doesn't let an
  attacker silently downgrade KDF strength: the derived key changes, so GCM auth-tag verification on `blobKey`
  fails closed and decryption throws. Checked this specifically since the outer file checksum
  (`file.js: computeChecksum`) is *unkeyed* SHA-256 — by itself that would only catch corruption, not tampering
  — but the AEAD tag on `blobKey` is what actually carries the integrity guarantee, and it does.
  Residual: an attacker with local write access to the container file can still cause a denial-of-service by
  corrupting `metadata`/`blob` (decrypt throws instead of silently degrading) — but that attacker already has
  write access to the disk, which is out of the program's threat model (out-of-scope: "attacks requiring...
  physical access to a user's device").

**`hydra/libraries/sodium-crypto`** — thin wrapper over `libsodium-wrappers` (secretbox, box, sealed box,
sign/verify, AEAD chacha20poly1305, argon2id `pwhash` with sensible hardcoded OPSLIMIT/MEMLIMIT). No parameter
confusion or nonce reuse spotted; nonces are freshly randomly generated per call, not derived/counter-based.

**`hydra/features/connected-origins`** — dApp connection permission store (`module/connections.js`,
`redux/selectors/trusted.js`)
This is pure state management (which origins are "trusted", their granted accounts/assets). The actual
postMessage/extension-transport origin verification lives in an external dependency
(`@exodus/window-rpc-transport`, referenced but not vendored into the `hydra` workspace) — that package isn't
in this repo, so it wasn't reviewable here. **This is the single highest-value place left to check** for a
malicious-website-signs-without-consent bug class, but it's outside the cloned source.

## Not yet reviewed (good next targets, roughly in priority order)

1. `hydra/libraries/bip39`, `bip32`, `slip10`, `key-utils`, `key-identifier` — seed/key derivation correctness
   (wrong derivation path handling, mixing coin types, off-by-one in hardened-index logic would be critical-severity)
2. `hydra/features/keychain`, `hydra/features/tx-signer`, `hydra/features/message-signer` — where user consent
   is actually gated before a signature is produced; look for any path that signs without the confirmation step,
   or where a crafted RPC payload could get auto-approved via `isAutoApprove`
3. `hydra/adapters/storage-unsafe-desktop` — name implies weaker guarantees; worth confirming it's never used
   for secret material (seed/private keys) and only for genuinely non-sensitive data
4. `hydra/adapters/storage-encrypted`, `hydra/libraries/seco-file` / `seco-keyval` / `seco-rw` — storage layer
   built on top of `secure-container`; check key management (where does the encryption key/passphrase actually
   come from, is it ever logged or held in a way another process/extension could read)
5. `hydra/libraries/browser-extension-channels`, `browser-extension-rpc` (background/content/inapp bridges) —
   re-check once/if `@exodus/window-rpc-transport` source is available, since that's where origin checks for
   `postMessage` would live
6. npm packages `@exodus/keychain`, `@exodus/safe-string`, `@exodus/errors`, `@exodus/sentry-client` (listed
   individually in scope) — not yet pulled; worth diffing their published npm tarball against what ships in
   `hydra` in case an older/patched version is what's actually distributed

## How to continue

Tell me which numbered item to go after next, or hand me a specific file/PR/commit if you already have a lead.
Findings with a working PoC (a script/unit test demonstrating the issue, not just "this looks off") are what
the program actually pays on — so the next pass should end in a runnable repro, not just a code pointer.
