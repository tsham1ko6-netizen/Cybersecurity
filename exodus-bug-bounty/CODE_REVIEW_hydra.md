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

**`hydra/libraries/bip39`** (`src/index.js`) — mnemonic generation/validation
`generateMnemonic` restricts `bitsize` to the standard set {128,160,192,224,256} and pulls entropy from the
same CSPRNG-backed `randomBytes`. `mnemonicToEntropy` recomputes and asserts the SHA-256 checksum bits before
accepting a mnemonic — no bypass path found (a mnemonic with a forged checksum throws). Entropy buffers are
`.fill(0)`'d on the error/return paths that convert to hex/buffer, limiting how long derived entropy sits in
memory.

**`hydra/libraries/bip32`** (`src/hdkey.js`) and **`hydra/libraries/slip10`** (`src/hdkey.js`) — HD derivation
Standard BIP32 child-key derivation (`CKDpriv`/`CKDpub`), correctly retries `deriveChild(index + 1)` on the
`IL >= n` / point-at-infinity edge case per spec instead of silently producing a bad key. SLIP10 (ed25519,
hardened-only) matches the reference spec, including hashing the seed through `"ed25519 seed"` before
derivation so the same seed bytes can't be reused directly as secp256k1 material. `HDKey#derive(path)` path
parsing rejects indices `>= HARDENED_OFFSET` and a malformed negative index fails closed (`Buffer.writeUInt32BE`
throws on negative input) rather than silently deriving the wrong key.

**`hydra/libraries/key-utils/src/derivation-path.js`** — path validation
Explicitly defends against the known real-world BIP32 footgun (an unhardened child derived after a hardened
one, which combined with an xpub leak can expose the parent xpriv): `assertValidDerivationPath` and the
`DerivationPath` class both reject "hardened index after unhardened index" paths. Also guards against the
"`m/0'somestring`" style injection that a naive regex without `^$` anchors would accept (`bip32-path`'s own
regex doesn't anchor; this library re-validates on top of it).

**`hydra/features/keychain/module/keychain.js`** — the actual in-memory key store used for signing
Lock/unlock semantics: `#getPrivateHDKey` only skips the "are private keys unlocked" check when called with
an internal `Symbol` that isn't reachable from outside the class. The ed25519/secp256k1/sodium/cardano signer
sub-modules are handed the bound method but can't produce that symbol, so every actual **signing** path
(`signBuffer` → `secp256k1.signBuffer`/`ed25519.signBuffer`/etc.) enforces the lock. `exportKey`/`getPublicKey`
intentionally bypass the lock for *public*-key-only derivation (needed to show balances/addresses while
locked) — that's a deliberate, sane design, not a leak: `exportKey` still gates `exportPrivate` behind
`#assertPrivateKeysUnlocked`. No path found where `signBuffer` succeeds while a seed is locked.

**`hydra/adapters/storage-unsafe-desktop`** — plain, unencrypted `fs`-backed key/value storage
This is intentionally unencrypted by design (its own README says so up front: "'Unsafe' = no encryption out
of the box"), meant to be composed with `secure-container`/`storage-encrypted` for anything sensitive. Nothing
in this adapter itself mishandles secrets — whether it's *wired up* correctly (i.e., never handed a seed/
private key directly by some SDK config) would require seeing actual app-level dependency injection config,
which isn't in this repo.

## Not yet reviewed (good next targets, roughly in priority order)

1. `hydra/adapters/storage-encrypted`, `hydra/libraries/seco-file` / `seco-keyval` / `seco-rw` — storage layer
   built on top of `secure-container`; check key management (where does the encryption key/passphrase actually
   come from, is it ever logged or held in a way another process/extension could read)
2. `hydra/libraries/browser-extension-channels`, `browser-extension-rpc` (background/content/inapp bridges) —
   the actual `postMessage` origin check lives in `@exodus/window-rpc-transport`, an external dependency not
   vendored into this workspace, so it couldn't be reviewed here — still the single highest-value unreviewed
   spot for a "malicious site signs without consent" bug class
3. `hydra/features/keychain/module/crypto/*.js` (ed25519.js, secp256k1.js, sodium.js, cardano.js, schnorr-z.js) —
   read the dispatch/glue in `keychain.js`, but not yet the per-curve signing implementations themselves
4. npm packages `@exodus/keychain`, `@exodus/safe-string`, `@exodus/errors`, `@exodus/sentry-client` (listed
   individually in scope) — not yet pulled; worth diffing their published npm tarball against what ships in
   `hydra` in case an older/patched version is what's actually distributed
5. `hydra/features/wallet-accounts`, `hydra/features/address-provider` — where addresses/accounts get computed;
   a bug here (wrong account derivation, address reuse across assets) would be high severity but is a large surface

## Status

No exploitable vulnerability found after this pass across crypto primitives, encoding, the on-disk encrypted
container format, sodium wrapper, BIP39/BIP32/SLIP10 derivation, derivation-path validation, and the in-memory
keychain's lock/unlock and signing gate. This tracks with a codebase that runs CodeQL plus AI-assisted review
(Codex + Copilot) on every PR — the "easy" bugs in core crypto are unlikely to still be there. The remaining
open items above (especially #2, the postMessage/RPC origin-check boundary) are where a real finding is most
likely to still be sitting, but reviewing them needs source this session doesn't have access to, or is a much
larger surface (#5) that needs more budget than one pass.

## How to continue

Tell me which numbered item to go after next, or hand me a specific file/PR/commit if you already have a lead.
Findings with a working PoC (a script/unit test demonstrating the issue, not just "this looks off") are what
the program actually pays on — so the next pass should end in a runnable repro, not just a code pointer.
