# Reproducing: @exodus/keychain unlock() doesn't enforce documented seed-switch protection

```bash
npm install @exodus/keychain@12.0.0
node keychain-silent-seed-switch.mjs
```

Requires network access to the npm registry (this installs the real, currently-published package --
no mocks). Expected output on an unpatched version shows `unlock(seedB) did NOT throw`.
