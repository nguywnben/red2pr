# Red2PR Official Landing Page (`website/`)

Static marketing website for **Red2PR**, built with **React 19 + TypeScript + Vite 6 + Meta Astryx (`0.7.4`, Neutral theme)** and configured for GitHub Pages deployment at `https://nguywnben.github.io/red2pr/` (`base: "/red2pr/"`).

## Local Development & Verification

Run commands from `website/` (isolated from the main Red2PR workspace lockfile and runtime):

```bash
cd website
pnpm install --frozen-lockfile

# Local development server -> http://127.0.0.1:5180/red2pr/
pnpm dev

# Typecheck + production static build -> website/dist
pnpm build

# Preview production bundle under the exact /red2pr/ base path -> http://127.0.0.1:4180/red2pr/
pnpm preview
```

## GitHub Pages Deployment

`.github/workflows/pages.yml` builds **only** `website/` and deploys `website/dist` via official GitHub Pages Actions (`actions/configure-pages`, `actions/upload-pages-artifact`, `actions/deploy-pages`).

To publish on GitHub:
1. In `https://github.com/nguywnben/red2pr/settings/pages`, set **Build and deployment → Source** to **GitHub Actions**.
2. Push `website/` and `.github/workflows/pages.yml` to `main` (or trigger **Deploy Website to GitHub Pages** manually via `workflow_dispatch`).
