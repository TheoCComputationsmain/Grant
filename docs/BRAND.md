# Grant brand system

Grant should feel like quiet infrastructure: paper, ink, glass, and a hint of circuitry. It is not a neon developer tool.

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| Paper | `#FAF8F5` | Primary background |
| Paper deep | `#F2EFE8` | Gradient shadow |
| Ink | `#2B1B20` | Body copy |
| Burgundy | `#6d2038` | Primary action, seal, brand mark |
| Burgundy soft | `#8C3A55` | Gradients |
| Muted | `#7D6B69` | Secondary copy |
| Hairline | `#E6E1D6` | Borders and dividers |

The PWA manifest and `theme-color` use Paper `#FAF8F5` and Burgundy `#6d2038`. No fluorescent greens, electric blues, cyberpunk purples, or glow-heavy gradients.

## Type

- Headlines: serif (`ui-serif, Georgia, Cambria, serif`), tight tracking, italic accent in burgundy.
- Body: system sans, comfortable line height.
- Code and IDs: monospace, smaller, paper background.

## Surfaces

- Cards use translucent white glass (`rgba(255,255,255,.58)` → `.30`) with a 20px blur, soft hairline border, and a subtle inner highlight.
- Corners are generous: 26px for large cards, 14px for buttons and inputs.
- Shadows are warm and diffuse, never black or heavy.

## Circuit motif

A faint SVG pattern sits behind the page: orthogonal traces, small nodes, and square components inspired by transparent hardware design. It is decorative, `aria-hidden`, and low contrast (`rgba(109,32,56,.085)`).

Motion is a slow dash-flow on the traces. It must respect `prefers-reduced-motion`.

## Voice

Short, calm, concrete.

Good:

- “Allow this, or not?”
- “Exact scope”
- “A decision, not a dashboard.”
- “Nothing was allowed.”

Avoid:

- “Revolutionary AI-powered security”
- “Supercharge your workflow”
- Hype, exclamation marks, fear, urgency.

## Core screens

1. **Landing** — one promise, one sample agent message, one live approval preview.
2. **Approval** — who, what, exact scope, expiry, three decisions.
3. **Done** — plain confirmation with a path to workspace and docs.
4. **Workspace / console** — usage meter, trial state, requests, permissions, bookmark key, install snippet.
5. **Pricing** — four calm columns, Plus highlighted, monthly/annual toggle, Enterprise contact CTA.
6. **Protected by Grant** — end-user view of authorized agents with a quiet builder CTA.
7. **Ops** — token-gated aggregate counters, no raw activity feed or glitter.
8. **Docs** — copy-paste first, concepts second.
9. **Checkpoint** (`/approve/{req_id}`) — who/what/scope, then **Continue**, **Always allow**, and a subtle **Cancel**.
10. **Signup** (`/signup`) — quiet sign-up with a mandatory **Add Shortcut** PWA install before continuing.
11. **Receipt** (`/receipt/{req_id}`) — public signed receipt, no blank close screen.
12. **Account** (`/account`) — standalone installed app for keys, rules, billing, and history.

Every screen should work on mobile without horizontal scrolling.

## Exact copy

These strings are contract, not suggestions. Do not paraphrase them:

- Every UI screen shows **“Grant never sees your credentials or payment details. It only records what you allowed.”**
- Persistent watermark: **“● Protected by Grant · Zero-custody consent infrastructure”**
- Builder CTA: **“Get Your Free API Key →”**
- Pricing: Free $0; Plus **$20/mo / ₹2,400**; Pro **$150/mo**; Enterprise **$4,000/mo** (contact CTA). Annual figures are display-only; hosted checkout is monthly-only.
- Cashfree phone placeholder is the server-only `9999999999`. Grant never collects a phone number, password, or card detail in the UI.

## PWA

- Assets: `/manifest.webmanifest`, `/sw.js`, `/icons/icon-192.svg`, `/icons/icon-512.svg`.
- Manifest: `start_url: /account`, `display: standalone`, Paper `#FAF8F5` and Burgundy `#6d2038` for theme/background.
- The install step is part of the sign-up flow: **Add Shortcut** must be offered and completed before continuing to `/account`. Keep the prompt calm and explain that it only adds a home-screen shortcut.
