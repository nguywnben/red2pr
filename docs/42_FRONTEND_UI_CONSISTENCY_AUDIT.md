# Frontend UI-S01–UI-S21 Consistency Audit

**Status:** Owner-approved Red2PR UI/UX rebuild audit, 2026-11-02.  
**Design direction:** Astryx Neutral, Apple-inspired minimalism, enterprise developer SaaS.  
**Authority:** [Screen and interaction contracts](34_SCREEN_AND_INTERACTION_CONTRACTS.md), [frontend UX flow blueprint](41_FRONTEND_UX_FLOW_BLUEPRINT.md), ADR-025 and ADR-040.  
**Boundary:** Frontend presentation and interaction only. This audit does not start U31 or certify a live provider, production account, deployment, or external service.

## Shared design and interaction contract

| Area | Shared implementation | Audit result |
|---|---|---|
| Theme and typography | Astryx Core/Neutral 0.7.4, generated theme registry, Neutral semantic tokens and shared page/header typography | Consistent light/dark tokens; no Core or Theme upgrade. |
| Application frame | Astryx AppShell, grouped SideNav, responsive mobile drawer, persistent theme/account controls, workspace context and SSE status | One shell for workspace and owner operations; account/recovery/setup surfaces retain their appropriate standalone flow. `/system` is owner-gated and only appears in navigation for the instance owner. |
| Page rhythm and surfaces | Shared `red2pr-page-stack`, `red2pr-page-header`, `red2pr-card-section`, `red2pr-form-stack`, and `red2pr-field` token rules | Pages use the same spacing, widths, field alignment and surface treatment while retaining task-specific hierarchy. |
| Inputs, links and focus | Astryx TextInput/Link/Selector where supported; shared native-control token rules for native form controls | TextInput focus remains Astryx-owned; keyboard focus remains visible. Pointer/keyboard/hover/active/blur/selection behavior is covered by Login headless evidence. |
| Tables and dense data | Astryx Table wrapper, compact density and row dividers | Analytics tables now keep readable minimum column widths and use Astryx's keyboard-accessible horizontal scroller on narrow screens. |
| States and status | Shared StateView, semantic status labels/glyphs, redacted error summaries, correlation IDs and live region | Loading, empty, error, offline, forbidden, stale/degraded and proof states remain explicit where applicable; color is not the only signal. |
| Protected actions | Existing Button/Dialog/step-up and API mutation flows | Confirmation, RBAC, revision, idempotency and audit behavior remain in feature flows; no mock business action or backend contract change was introduced. |

## Screen-by-screen matrix

“Flow evidence” names the focused suite that exercises the screen's real typed-client behavior, negative states and applicable accessibility checks. The browser column names direct render evidence; other screens inherit the shared AppShell/theme controls and are covered by their page-level flow suite, not by an individual screenshot.

| UI | Route / user goal | Flow evidence | Cross-screen audit and browser evidence |
|---|---|---|---|
| S01 | `/setup/*` — resume first-run readiness from persisted server state | `setupWizardFlows.test.tsx` | Shared page/card/form/state styles; preserves setup phase, consent and readiness gates. |
| S02 | `/login`, `/login/recovery`, OIDC callback — sign in or recover access | `authFlows.test.tsx`, `cleanLogin.test.tsx` | Dedicated compact auth surfaces; no owner-claim tab. Login pointer/keyboard focus and recovery-link states have light/dark screenshots and computed-style evidence. |
| S03 | `/w/:ws/overview` — find the most relevant repair outcome | `analyticsFlows.test.tsx` | Shared shell, analytics and denominator/watermark language. Headless renders: 1440 light/dark, 390 and 320 light. |
| S04 | `/w/:ws/repositories` — find and onboard an authorized repository | `repositoriesAndPoliciesFlows.test.tsx` | Shared filters, table, forms, permission states and bulk preview/step-up flow. |
| S05 | `/w/:ws/repositories/:repo` — inspect effective policy and repository activity | `repositoriesAndPoliciesFlows.test.tsx` | Same repository surface/form/table language as S04; tab keyboard and policy dry-run behavior are exercised. |
| S06 | `/w/:ws/pipelines` — find a provider run/job and inspect bounded evidence | `pipelinesFlows.test.tsx` | Shared table/state treatment; log and artifact access remains bounded and demand-driven. |
| S07 | `/w/:ws/repairs` — track repairs and start only eligible work | `repairsListFlows.test.tsx` | Shared list, empty/error and action hierarchy; repair eligibility remains server-authoritative. |
| S08 | `/w/:ws/repairs/:id` — follow diagnosis through proof and publication | `repairDetailEvidence.test.tsx` | Shared timeline/state vocabulary; AI hypothesis, local proof and remote outcome remain distinct. |
| S09 | `/w/:ws/prs` — review draft publication and remote CI checks | `pullRequestsPage.test.tsx` | Shared evidence/status language; unknown remote results remain unknown. |
| S10 | `/w/:ws/approvals` — review and decide a protected action | `approvalsInboxFlows.test.tsx`, `telegramIntentConfirm.test.tsx` | Shared approval context, step-up and decision feedback; no optimistic approval result. |
| S11 | `/w/:ws/agents` — inspect bounded agent capabilities | `agentsFlows.test.tsx` | Shared page/card hierarchy; capability denials and bounded steps retain their existing contract. |
| S12 | `/w/:ws/models` — configure models, budgets and capability probes | `modelsFlows.test.tsx`, `fallbackPolicyCard.test.tsx` | Shared field, masked-secret and cost state patterns; probe cost confirmation and read-only RBAC remain intact. |
| S13 | `/w/:ws/workers` — inspect worker readiness and fleet trust | `workersFlows.test.tsx` | Shared trust/status vocabulary; enrollment and quarantine behavior remain permissioned. |
| S14 | `/w/:ws/queues` — inspect durable jobs and dead-letter work | `queuesFlows.test.tsx` | Shared table, state and scoped-confirmation patterns; lease/fencing behavior stays server-owned. |
| S15 | `/w/:ws/integrations` — connect or reconcile GitHub/GitLab/customer relay | `githubIntegrationsFlows.test.tsx`, `gitlabIntegrationsFlows.test.tsx`, `pollingReconcilerFlows.test.tsx`, `relayConfigCard.test.tsx` | Provider panels share forms, tables and error states; customer-operated relay remains explicit. |
| S16 | `/w/:ws/notifications` — review inbox and manage destinations | `notificationsFlows.test.tsx` | Shared inbox/state/form patterns; secret material remains write-only/one-time and test-send is explicit. |
| S17 | `/w/:ws/analytics` — inspect bounded funnel/costs and export a report | `analyticsFlows.test.tsx` | Funnel and ledger use Astryx Table; headless renders at 1280 and 390 light. Narrow tables scroll horizontally with a visible instruction and no page overflow. |
| S18 | `/w/:ws/security` — inspect grants, audit and security controls | `securityFlows.test.tsx` | Shared masked metadata, permission and protected-action language. |
| S19 | `/w/:ws/members` — manage members, invitations and scoped grants | `membersFlows.test.tsx` | Shared form/table/state patterns; last-admin, break-glass, step-up and revocation guards stay in place. |
| S20 | `/system` — instance owner checks status and performs safe operations | `systemFlows.test.tsx` | Owner-only route and nav are checked; headless 1280 light render has no axe violations or runtime errors. |
| S21 | `/account` — manage personal sessions, MFA and Telegram link | `authFlows.test.tsx`, `telegramLinkCard.test.tsx` | Personal account scope remains separate from workspace settings; session/MFA/link flows retain their confirmation and one-time display behavior. |

## Render and interaction evidence

`docs/evidence/frontend-rebuild-20261102/ui-shell-preview.cjs` runs Playwright Core headlessly, serves the app from loopback, blocks all non-local network requests, and supplies deterministic local API fixtures. It captures:

- `overview-light-desktop-final.png`, `overview-dark-desktop-final.png`, `overview-light-mobile-final.png`, `overview-light-mobile-320-final.png`.
- `analytics-light-desktop-final.png`, `analytics-light-mobile-final.png`, `system-light-desktop-final.png`.
- `ui-shell-preview-final.json` with route, viewport, active theme, API paths, navigation geometry, table scroll widths, Axe result and page errors.

The final preview asserts no document overflow, no overlapping/out-of-viewport top-nav controls at 390px and 320px, zero Axe violations and zero page runtime errors across all six render variants. The login interaction suite separately captures pointer, keyboard, hover, active, blur and text-selection states in light and dark mode.

## Limitations and non-regression boundary

- Browser preview data is local fixture data and is not production or live-provider evidence. No paid API, external IdP, real account, production data, push, merge, deploy or publish was used.
- Screens are mapped individually to their focused flow suites, but screenshots are representative rather than one screenshot per screen. The shared shell, tokens and responsive form/table rules are reused across routes; screen-specific journeys remain validated by the page suites.
- `astryx doctor` recognizes the CLI-generated theme registry and reports no failures. It retains a CLI 0.7.5/Core 0.7.4 alignment warning and cannot prove the external Figtree font service loads. The accepted Core/Theme 0.7.4 pins were preserved.
- The production build retains its existing non-fatal vendor-chunk size advisory. Vitest may emit existing React `act(...)` diagnostics in a few integration tests.
- U31 and all post-P4 implementation remain unstarted.
