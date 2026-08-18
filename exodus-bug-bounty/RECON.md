# Exodus Recon Playbook (run on your own machine — this sandbox has no internet egress)

This session's network is locked to an allowlist (npm/pypi/github/anthropic only), so I can't reach
`exodus.io` from here. Run the steps below yourself; send me the output (host lists, JSON, screenshots,
suspicious findings) and I'll help triage/write up whatever looks real.

Every request must carry `User-Agent: h1-sham1k (security research)` per program rules, or your IP risks
being blocked. `recon.sh` below sets this globally for every tool that supports it.

## 0. Guardrails (bake these in before running anything)

Never touch, even accidentally via a wildcard match:
```
exchange-server*.exodus.io  exchange-p.exodus.io  *.xoswap.com  xoswap-graphql*.a.exodus.io
*.passkeys.foundation  *.passkeys.network  *.grateful.me
exodus.atlassian.net  support.exodus.com  support-helpers.a.exodus.io  slack-invite.exodus.com
get.exodus.*  exodusstore.blob.core.windows.net  *.atp-exodus.com
```
Never submit a request that would create a real swap/exchange order, submit the contact form, or open
a support ticket. Never brute-force, fuzz for volume, or run anything that could degrade the service —
that needs prior written OK from `bugbounty@exodus.com`.

## 1. Subdomain enumeration (passive first)

```bash
# passive sources, no direct target contact
subfinder -d exodus.io -all -silent -o subs_exodus_io.txt
subfinder -d exodus.com -all -silent -o subs_exodus_com.txt

# certificate transparency (also passive)
curl -s "https://crt.sh/?q=%25.exodus.io&output=json" | jq -r '.[].name_value' | sort -u >> subs_exodus_io.txt
curl -s "https://crt.sh/?q=%25.exodus.com&output=json" | jq -r '.[].name_value' | sort -u >> subs_exodus_com.txt

sort -u subs_exodus_io.txt -o subs_exodus_io.txt
sort -u subs_exodus_com.txt -o subs_exodus_com.txt
```

Manually append the known staging pattern: for every asset name in scope, also try prefixing/suffixing
`-s` per the program's staging convention, e.g. `bitcoin.a.exodus.io` → `bitcoin-s.a.exodus.io`.

## 2. Filter to in-scope, then probe for live hosts

```bash
grep -E '(^|\.)exodus\.io$|\.a\.exodus\.io$' subs_exodus_io.txt > scope_io.txt
grep -E 'exodus\.com$' subs_exodus_com.txt > scope_com.txt

# drop anything matching the excluded list in SCOPE.md before probing
grep -vE 'exchange-server|exchange-p\.|xoswap|passkeys\.|grateful\.me|atlassian|support\.|support-helpers|slack-invite|get\.exodus|atp-exodus' \
  scope_io.txt scope_com.txt | sort -u > in_scope_hosts.txt

httpx -l in_scope_hosts.txt -H 'User-Agent: h1-sham1k (security research)' \
  -title -status-code -tech-detect -follow-redirects -silent -o live_hosts.txt
```

## 3. Light, non-destructive checks per live host

- **Headers**: `curl -sI -H 'User-Agent: h1-sham1k' https://HOST` — look for missing `Strict-Transport-Security`,
  permissive `Access-Control-Allow-Origin: *` on endpoints that return account/auth data, missing `X-Frame-Options`/CSP
  on pages with sensitive actions (clickjacking).
- **CORS probe**: send `Origin: https://evil.example` and check if it's reflected + `Access-Control-Allow-Credentials: true`.
- **JS source review**: pull all bundled JS from the app (`fiat.a.exodus.io`, `kyc.a.exodus.io`, `pay.exodus.io`,
  `login.exodus.com`) and grep for API base URLs, feature flags, internal hostnames, leftover debug endpoints.
  This is usually higher-signal than scanning.
- **Auth/IDOR on KYC & Ramp flows** (`kyc.a.exodus.io`, `fiat*.a.exodus.io`): if you can create a throwaway
  test account, check whether object IDs (KYC application ID, order ID) are sequential/guessable and whether
  one authenticated user can read another's by swapping the ID — classic high-value wallet-adjacent finding.
- **Subdomain takeover**: for any host resolving to a CNAME pointing at an unclaimed cloud resource
  (Azure/AWS/Heroku/etc — note `exodusstore.blob.core.windows.net` is explicitly *not theirs*, so a dangling
  pointer there is a real takeover candidate, not a dupe of that excluded entry):
  ```bash
  dnsx -l in_scope_hosts.txt -cname -silent | tee cnames.txt
  # then check each CNAME target for "not found"/"no such app" style responses
  ```
- **Nuclei — curated, not full blast**: only exposure/misconfig templates, never brute-force/dos/fuzz tags:
  ```bash
  nuclei -l live_hosts.txt -H 'User-Agent: h1-sham1k (security research)' \
    -tags exposure,misconfig,cve -etags dos,fuzz,brute-force \
    -rate-limit 10 -silent -o nuclei_findings.txt
  ```
  Rate-limit low; this is still "extended scanning" territory if you crank it up — keep it polite.

## 4. Client apps / desktop wallet

- Download the Desktop Wallet installer, check auto-update mechanism for signature verification / MITM risk
  on the update channel (do this passively — inspect the update manifest/URLs, don't tamper with a live server).
- Static review of Play Store / App Store APK/IPA (permissions, exported components, hardcoded endpoints)
  is fair game without touching Exodus infra at all.

## 5. Reporting

One vulnerability per report; list every affected in-scope endpoint under that single report if the same
root cause repeats. Include: exact steps, request/response, impact, and a minimal PoC. See `SCOPE.md` for
the reward tier of whatever asset group you land in.
