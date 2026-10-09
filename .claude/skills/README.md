# Agent skills for Claude Code sessions in this repository

| Skill | What it does | Version | Source | Licence |
|---|---|---|---|---|
| `archify` | Architecture, workflow, sequence, data-flow and lifecycle diagrams as standalone HTML | 3.0.1 | https://github.com/tt-a1i/archify | MIT (`archify/LICENSE`, `archify/THIRD_PARTY_NOTICES.md`) |

It needs Node.js 18+ and nothing else at run time (`node .claude/skills/archify/bin/archify.mjs doctor`). Not shipped with the product.
The TLS diagram's source is `docs/how-it-works/tls.workflow.json`; the result is `site/how-it-works/tls.html`.
