# InboxShield GitHub Action (`zColdWater/inboxshield-action@v1`)

[![Email Security](https://inbox-checker.appwrite.network/badge/inbox/stripe.com.svg)](https://inbox-checker.appwrite.network/?domain=stripe.com&ref=gh-inboxshield-action-badge)
[![GitHub Release](https://img.shields.io/badge/release-v1.0.0-2563eb)](https://github.com/zColdWater/inboxshield-action/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

**Zero-dependency GitHub Action to continuously monitor domain email deliverability, recursive SPF 10-lookup limits (RFC 7208), DKIM public keys, DMARC `p=quarantine/reject` enforcement, MTA-STS, and BIMI.**

Prevent silent Gmail and Microsoft 365 spam-folder placement caused by broken SPF `PermError` chains or missing DMARC policies.

- **Free 6-Phase Interactive DNS & DMARC Simulator:** [https://inbox-checker.appwrite.network](https://inbox-checker.appwrite.network/?ref=gh-inboxshield-action)
- **Free SPF Lookup Flattener:** [https://inbox-checker.appwrite.network/spf-flattener](https://inbox-checker.appwrite.network/spf-flattener?ref=gh-inboxshield-action)
- **Single-Domain Conflict-Free SPF/DMARC Fix Unlock ($2 Launch Special, ~~$9~~):** [https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)
- **OmniForge 3-in-1 Complete Suite ($5 Launch Special, ~~$29~~):** [https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack)

---

## Quick Start (`uses: zColdWater/inboxshield-action@v1`)

```yaml
name: Weekly Email Deliverability Gate
on:
  schedule:
    - cron: "0 9 * * 1"
  workflow_dispatch:

jobs:
  dmarc-spf-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Check SPF Lookup Budget & DMARC Policy
        uses: zColdWater/inboxshield-action@v1
        with:
          domain: "yourcompany.com"
          min-score: "80"
          require-dmarc-enforcement: "true"
```

### Action Inputs & Outputs

| Input | Default | Description |
| :--- | :---: | :--- |
| `domain` | *(required)* | Root or sending domain to audit (e.g. `yourcompany.com`). |
| `min-score` | `"70"` | Minimum passing deliverability score (`0-100`). |
| `require-dmarc-enforcement` | `"false"` | Fail workflow if DMARC is missing or stuck in `p=none`. |

Outputs: `score`, `spf-lookups`, and `dmarc-policy`.

---

## Online Workbench vs. Single-Domain Fix Unlock ($2 Launch Special)

| Capability | Free Action & Online Audit | Single-Domain Fix ($2 ~~$9~~) | Complete Suite ($5 ~~$29~~) |
| :--- | :---: | :---: | :---: |
| **6-Phase MX, SPF Tree, 24-Selector DKIM, DMARC, BIMI & DNSBL Diagnosis** | **100% Free** | **Included** | **VibeShield + InboxShield + CiteReady** |
| **Conflict-Free Merged & Flattened SPF + Exact Registrar TXT Values** | Preview | **Unlocked ([Get for $2](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield))** | **Unlocked Across All 3 Suites ([Get for $5](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack))** |

## License

MIT © OmniForge · Agent Arena Studio (`agentarenastudio@proton.me`)
