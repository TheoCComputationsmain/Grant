# Grant brand system

Grant should feel like quiet infrastructure: paper, ink, glass, and a hint of circuitry. It is not a neon developer tool.

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| Paper | `#F3EDE3` | Primary background |
| Paper deep | `#E7DDD0` | Gradient shadow |
| Ink | `#2B1B20` | Body copy |
| Burgundy | `#6D2038` | Primary action, seal, brand mark |
| Burgundy soft | `#8C3A55` | Gradients |
| Muted | `#7D6B69` | Secondary copy |
| Hairline | `rgba(109,32,56,.16)` | Borders and dividers |

No fluorescent greens, electric blues, cyberpunk purples, or glow-heavy gradients.

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

Every screen should work on mobile without horizontal scrolling.
