# Frontend engineering — Astryx integration and React contracts

## Binding choice
- **Chosen stack:** React 19, TypeScript strict mode, Vite, Astryx Design System (`@astryxdesign/core`, `@astryxdesign/theme-neutral`) with pinned exact versions. Use CSS theme imports documented by Astryx (`reset.css`, `astryx.css`, neutral theme) and Red2PR token overrides. `@astryxdesign/cli` is a development tool, not a production dependency unless justified.
- **Backend remains Python/FastAPI**. Compile frontend to static assets, serve same-origin at `/` behind Caddy/ingress, proxy `/api/v1/*` and `/events/*` to FastAPI. Avoid unnecessarily running Next.js/Node runtime in production.
- React handles presentation and interaction only; privileged decisions remain server-side. All UI actions call typed API endpoints; UI roles are affordances, never authorization decisions.

## Design system composition
| UI concern | Proposed implementation | Hard guardrail |
|---|---|---|
| Layout | Astryx containers, app shell/side navigation *when validated* | verify component existence with official docs/CLI; create wrapper if absent |
| Navigation | React Router + reusable navigation item schema | keyboard focus, current route, mobile drawer, accessible labels |
| Data fetching | TanStack Query + generated OpenAPI TypeScript client | no duplicated ad-hoc DTO shapes; invalidate via authoritative API response |
| Event stream | SSE for progress with last-event replay cursor | REST fetch reconciliation; no event lost assumption |
| Forms | Typed schema validation (e.g., Zod) | server validates again; prevent mass assignment |
| Styling | Astryx theme-neutral tokens + supported StyleX build integration (verified peer dependency), scoped CSS for adapters | protect CSS cascade layers; theme compatibility tests |
| Data grid | Astryx table if supports required behaviors; otherwise vetted data-grid with Astryx wrapper | huge logs are virtualized; row-level a11y and sorting |
| Code diffs | Monaco/diff component with sanitization | never execute HTML/JS from logs or patches |
| Terminal/logs | virtualized read-only text viewer | no arbitrary raw HTML, avoid clipboard surprises |
| Charts | vetted chart lib + Astryx tokens | provide accessible text/table fallback |
| i18n | EN first, VN translation-ready | no hardcoded locale in business rules |

## Component architecture
`app/` bootstrap/providers/router, `features/<bounded-context>/` routes/components/hooks, `shared/api/` OpenAPI client, `shared/ui/` Astryx adapters, `shared/auth/`, `shared/events/`, `shared/theme/`, `shared/i18n/`, `shared/test/`. Shared UI adapters expose a stable Red2PR interface, so Astryx Beta API changes require local adapter updates rather than global rewrites.

## Astryx CLI safety
Astryx docs: `npm install @astryxdesign/core @astryxdesign/theme-neutral @astryxdesign/cli`, `npx astryx init`. The initializer can add agent guide files, **never allow it to overwrite root `AGENTS.md` without backup, diff and controlled merge**. Use official CLI for component props and examples; don't invent `@astryxdesign/*` exports, including symbols omitted from docs. Example Vite source: https://github.com/facebook/astryx/tree/main/apps/example-vite.

## UX state standard
Each page supports `loading`, `empty`, `ready`, `stale`, `degraded`, `error`, `unauthorized`, `forbidden`, `offline` as applicable. Sensitive actions carry confirmation + policy preview + correlation ID. Graphs show denominators and date range. Session proof status uses text/icons as well as color.

## Browser/platform/security constraints
No Meta API key, GitHub token, GitLab PAT or Telegram bot token in client bundle/localStorage. Session cookies HttpOnly/Secure/SameSite as policy allows, CSRF mitigation, strict Content-Security-Policy, HTTPS for remotely exposed dashboard, safe rendering of untrusted logs and markdown. No eval/raw script injection. Browser bundle must not include sourcemapped sensitive application config.

## Frontend verification
Build/typecheck/lint, component tests, design-system upgrade snapshot regression, accessibility (keyboard + automated and manual screen reader sample), E2E across first-run and authorized workflows, mobile readability, timezone, error/offline/degraded states. Test protected route direct-navigation and cross-tenant resource ID guessing. Browser matrix is certified only after actual tests.

## Known risk & fallback
Astryx may change APIs/peer dependencies. Pin versions, maintain compatibility adapter; when missing an essential production component, implement a scoped accessible Red2PR component without abandoning Astryx tokens. This exception needs an ADR and tests. Do not treat use of Meta's design system as proof of using Meta AI models in hackathon judging.

## Source-verified Astryx surface — read 2026-10-27
Official source snapshot [facebook/astryx commit 2c7ef0e](https://github.com/facebook/astryx/tree/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9) was read without installing/running CLI. Core package reports0.7.5 and peer React>=19/StyleX^0.19.0; Red2PR choice remains React **major19**, not automatic future-major upgrade. Exact production pins require lockfile and build verification after code authorization.

| Component/source | Observed type surface | Red2PR consequence |
|---|---|---|
| [Button.tsx](https://github.com/facebook/astryx/blob/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9/packages/core/src/Button/Button.tsx) | label, isDisabled, isLoading, onClick | wrapper must not invent disabled/loading prop aliases; verify exports at integration |
| [Dialog.tsx](https://github.com/facebook/astryx/blob/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9/packages/core/src/Dialog/Dialog.tsx) | isOpen, onOpenChange; purpose required/form/info | controlled modal; focus/escape/screen-reader behavior must still be tested |
| [Table.tsx](https://github.com/facebook/astryx/blob/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9/packages/core/src/Table/Table.tsx) | TableProps plugins is a record; data/columns inherited | do not confuse BaseTableProps plugin array with public Table prop; virtualization capability not yet certified |
| [Vite example manifest](https://github.com/facebook/astryx/blob/2c7ef0e223ffbff3fc9d1264f5cc442fe50317e9/apps/example-vite/package.json) | React19, Vite8, TypeScript6, StyleX build plugin observed | example ranges are not Red2PR release lockfile; verify theme/css exports and bundler transforms before pinning |

Read status DOC/SOURCE_VERIFIED only; no component render, CLI command, build, accessible interaction or peer installation tested. Exact reset/theme CSS import/export strings in earlier design are **integration hypotheses**, not verified public exports. Gate FE-01 requires CLI/docs/export cross-check in a controlled disposable integration after permission, without running init against root AGENTS.md; capture before/after diff and merge only reviewed docs. UI toolkit fallback must preserve Astryx tokens and receive scoped ADR; no silent design system replacement.


[← Mục lục đặc tả](00_INDEX.md) · [Quyết định](20_DECISIONS_ADR.md) · [Truy vết](38_REQUIREMENTS_TRACEABILITY.md)
