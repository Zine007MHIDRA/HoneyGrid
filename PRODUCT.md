# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
- **Primary operators:** small security teams and MSSPs. Blue-team analysts who plant decoys in environments they defend and triage whatever trips them. Scanability and fast containment matter more to them than spectacle.
- **Showcase audience:** recruiters, peers and reviewers looking at HoneyGrid as the author's (Zine) security-engineering portfolio piece. They judge craft, clarity and technical depth, usually through the public landing page and a live demo.

## Product Purpose
HoneyGrid Sentinel is a cyber-deception and incident-response platform. Operators generate decoy assets: canary URLs, PDF beacons, fake AWS IAM keys, decoy `.env` secrets, decoy Git repos and KeePass vaults. When an adversary or scanner touches one, HoneyGrid captures network, geo and browser-hardware telemetry, scores the risk (Tor, VPN, datacenter, tooling), alerts on Discord, plots the hit on an attack radar map, and offers one-click containment. Success means an operator goes from "something tripped" to "I know who, from where, with what, and I've contained it" in under a minute.

## Positioning
The alert *is* the attacker. HoneyGrid doesn't watch traffic hoping to spot something bad. Anything touching a decoy is suspicious by definition, which means near-zero false positives, and each hit arrives already enriched with forensic telemetry.

## Operating Context
- Operators work in a signed-in SOC dashboard, often alongside Discord alerts. Typical flow: alert → dashboard → inspect incident → isolate IP or safelist it.
- Decoys are planted in real file shares, repos, cloud configs and documents.
- Deployed on Vercel serverless (SQLite in `/tmp`, so data is ephemeral there) and locally through `cli.py serve`.

## Capabilities and Constraints
- FastAPI backend. Templates are plain HTML files served as-is (no Jinja), with vanilla JS and Tailwind from a CDN. No build step.
- Strict CSP: scripts only from self/inline, `cdn.tailwindcss.com` and `unpkg.com`; fonts from Google Fonts; images from self, `data:` and CARTO/OSM tiles; network requests only to self and CARTO.
- **The decoy page (`decoy.html`) must stay a bland corporate 401 page.** It is attacker-facing and must never carry HoneyGrid branding.
- Public pages must never reveal canary URL formats (`/t/...`) or anything that helps an attacker tell a decoy from a real asset.
- Terminology: *decoy / trap / canary token*, *incident* (one trip), *threat score* (0–100), *safe list* (operator allowlist), *isolate* (SOAR containment).

## Brand Commitments
- Name: **HoneyGrid Sentinel**. Logo: `honeygrid/server/static/logo.jpg`.
- Voice: precise, calm, technical. Operator-to-operator, not marketing hype.

## Evidence on Hand
- A live dashboard with real or simulated incidents (`simulate_adversary.py` seeds data), usable for screenshots and demos.
- Public repo: https://github.com/Zine007MHIDRA/HoneyGrid. OK to link it.
- **There are no customers, usage metrics, testimonials or press.** Never fabricate them.

## Product Principles
1. **Signal over spectacle.** Every pixel in the operator UI should speed up triage; atmosphere is earned, never decorative.
2. **Every hit tells a story.** An incident is a person with a device, location and intent, so show it as that, not as a log line.
3. **Containment is one decision away.** Isolate and safelist sit next to the evidence that justifies them.
4. **Stealth is sacred.** Nothing public should weaken the deception.
5. **Honest showcase.** Demonstrate real mechanism and craft; claim nothing that isn't built.

## Accessibility & Inclusion
WCAG 2.1 AA for the operator UI and landing page: contrast in both themes, full keyboard operation of the drawer, palette and modals, and `prefers-reduced-motion` respected for the radar animation.
