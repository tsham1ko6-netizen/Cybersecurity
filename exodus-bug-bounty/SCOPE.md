# Exodus HackerOne Bug Bounty — Scope Reference

Program: Exodus (crypto wallet). HackerOne username used for testing: `sham1k`
(add `h1-sham1k` to `User-Agent` on every live request per program rules).

## Reward tiers by asset group

| Group | Range |
|---|---|
| Core (`*.exodus.io`, `*.a.exodus.io`) | $300 – $10,000 |
| XO Ramp | $500 – $18,000 |
| XO Swap | $500 – $18,000 |
| Smart Contracts | $500 – $20,000 |
| Passkey Assets | $500 – $20,000 (no assets listed yet) |
| Exodus Pay | $500 – $20,000 |
| Open-Source Libraries (SDK & Crypto) | $500 – $20,000 |
| Client Apps (mobile/desktop) | $500 – $10,000 |

## In-scope assets

**Core web**
- `*.exodus.io` (wildcard, High severity) — public website/subdomains/download links
- `*.a.exodus.io` staging — use `-s.` prefix, e.g. `bitcoin-s.a.exodus.io`, "safe for basic attack vectors"

**XO Ramp** (fiat on/off-ramp): `kyc.a.exodus.io`, `fiat.a.exodus.io`, `fiat-prod-fallback.a.exodus.io`, `fiat-p.a.exodus.io`

**XO Swap**: `nexotrack.exodus.io`, `nexotrack-p.exodus.io`, `ctr.a.exodus.io`
⚠️ Testing that *creates an order/exchange/swap* is explicitly forbidden program-wide — read-only/logic testing only.

**Exodus Pay**: `turing.exodus.io`, `pay.exodus.io`, `pay-admin.exodus.io`, `login.exodus.com`

**Smart Contracts**: Solana mainnet `xoUSDq85Rjsb6SbUwJyreFgeWQvxdkT7R3c3g7s6p5Y`, Solana `EQYRmLmkE7G7a2WQyojwrXg4SeguypCdnbm3ecncizsd`

**Open-source libraries** (code review, PoC required for reward):
- `npmjs.com/package/@exodus/sentry-client`
- `npmjs.com/package/@exodus/safe-string`
- `npmjs.com/package/@exodus/keychain`
- `npmjs.com/package/@exodus/errors`
- `github.com/ExodusOSS/hydra` (the whole SDK monorepo — mirror of private `exodus-hydra`)
- `github.com/ExodusOSS/crypto`
- `github.com/ExodusOSS/bytes`

**Client apps**: Play Store / App Store Exodus wallet, Desktop Wallet executable (Mac/Win/Linux)

## Explicitly OUT of scope (do not test)

- Exodus Exchange / XOSWAP live functionality (any order/exchange/swap creation) — hard rule, not just discouraged
- Contact form / support tickets (don't spam)
- `exchange-server*.exodus.io`, `exchange-p.exodus.io`, `xoswap-graphql*.a.exodus.io`, `api*.xoswap.com`, `dashboard*.xoswap.com` — listed Ineligible
- `passkeys.foundation`, `*.passkeys.foundation`, `*.passkeys.network`, `*.grateful.me` and related — Ineligible
- `exodus.atlassian.net` — not owned by Exodus
- `support.exodus.com`, `support-helpers.a.exodus.io`, `slack-invite.exodus.com` — 3rd party/no vulns
- **Exodus Browser Extension (the packaged product)** — Ineligible; but its *source in hydra* is separately in-scope since the repo is listed
- Known issues (do not resubmit): outdated Swagger/OpenAPI on embedded blockchain node APIs; hardcoded 3rd-party blockchain API keys; browser address-bar spoofing (patch in progress); 12-word seed phrases found in source (test-fixture noise)
- Social engineering, MITM/physical access, rate-limiting/brute-force or any DoS-risking test — require prior written permission from `bugbounty@exodus.com`

## Rules that affect methodology

- One report per root cause; group duplicate endpoints under one submission
- First correct report wins on duplicates
- Must be reproducible with clear steps or it's ineligible
- No extended/heavy scanning of infra without emailing `bugbounty@exodus.com` first with target + method + goal
