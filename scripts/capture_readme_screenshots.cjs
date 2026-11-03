"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const distDir = path.join(repoRoot, "apps", "web", "dist");
const outputDir = path.join(repoRoot, "docs", "assets", "screenshots");
const axeScriptPath = path.join(repoRoot, "apps", "web", "node_modules", "axe-core", "axe.min.js");
const { chromium } = require(
  path.join(repoRoot, "build", "browser-tools", "node_modules", "playwright-core"),
);

const browserPath =
  process.env.RED2PR_BROWSER_EXECUTABLE ??
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".woff2": "font/woff2",
};

const NOW_ISO = "2026-11-03T09:30:00Z";
const WS_ID = "0196f000-0000-7000-8000-000000000301";
const REPAIR_ID = "0196f000-0000-7000-8000-000000000201";
const RUN_ID = "0196f000-0000-7000-8000-000000000101";
const REPO_BILLING_ID = "0196f000-0000-7000-8000-000000000601";
const REPO_CHECKOUT_ID = "0196f000-0000-7000-8000-000000000602";
const REPO_PIPELINES_ID = "0196f000-0000-7000-8000-000000000603";
const PUBLICATION_ID = "0196f000-0000-7000-8000-000000000801";
const PUBLICATION_SECOND_ID = "0196eef0-0000-7000-8000-000000000802";

const workspace = {
  id: WS_ID,
  version: 1,
  created_at: "2026-10-27T08:00:00Z",
  updated_at: NOW_ISO,
  name: "Acme Platform",
  slug: "acme",
  status: "active",
  paused: false,
};

const mePayload = {
  user: {
    id: "0196f000-0000-7000-8000-000000000011",
    version: 1,
    created_at: "2026-10-27T08:00:00Z",
    updated_at: NOW_ISO,
    display_name: "Platform Maintainer",
    email: "maintainer@acme.example",
    status: "active",
  },
  session: {
    id: "0196f000-0000-7000-8000-000000000021",
    version: 1,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    user_id: "0196f000-0000-7000-8000-000000000011",
    expires_at: "2026-11-03T21:30:00Z",
    auth_strength: "mfa",
    step_up_at: NOW_ISO,
    grant_epoch: 1,
  },
  is_instance_owner: true,
  mfa_enabled: true,
  mfa_required_for_privileged: true,
  step_up_valid_until: "2026-11-03T09:45:00Z",
  workspaces: [workspace],
  memberships: [
    {
      id: "0196f000-0000-7000-8000-000000000031",
      workspace_id: WS_ID,
      version: 1,
      created_at: "2026-10-27T08:00:00Z",
      updated_at: NOW_ISO,
      user_id: "0196f000-0000-7000-8000-000000000011",
      role: "admin",
      repository_grants: [REPO_BILLING_ID, REPO_CHECKOUT_ID, REPO_PIPELINES_ID],
    },
  ],
  telegram_link: { linked: true, telegram_username: "acme_oncall", linked_at: NOW_ISO },
};

const setupCompleted = {
  version: 10,
  phase: "readiness_review",
  owner_claimed: true,
  completed_at: "2026-10-27T08:15:00Z",
  default_workspace_slug: "acme",
  readiness_tier: "ready_repair",
  steps: [],
};

const analyticsPayload = {
  workspace_id: WS_ID,
  range_start: "2026-10-04T09:30:00Z",
  range_end: NOW_ISO,
  repository_count: 3,
  funnel: [
    { key: "ingested", value: 28, numerator: null, denominator: null },
    { key: "eligible", value: 24, numerator: 24, denominator: 28 },
    { key: "executed", value: 21, numerator: 21, denominator: 24 },
    { key: "reproduced", value: 18, numerator: 18, denominator: 21 },
    { key: "locally_verified", value: 15, numerator: 15, denominator: 18 },
    { key: "publication_eligible", value: 14, numerator: 14, denominator: 15 },
    { key: "published_observed", value: 12, numerator: 12, denominator: 14 },
    { key: "remotely_verified", value: 11, numerator: 11, denominator: 12 },
  ],
  local_success_count: 15,
  remote_success_count: 11,
  unknown_count: 1,
  pending_count: 2,
  abstained_count: 3,
  costs: [
    {
      currency: "USD",
      settled: "4.820000",
      estimated_unsettled: "0.340000",
      total: "5.160000",
      unknown_rows: 0,
      usage_rows: 42,
    },
  ],
  watermark: NOW_ISO,
};

const repositoriesPayload = {
  items: [
    {
      id: REPO_BILLING_ID,
      workspace_id: WS_ID,
      version: 3,
      created_at: "2026-10-27T08:20:00Z",
      updated_at: NOW_ISO,
      connection_id: "0196f000-0000-7000-8000-000000000501",
      provider: "github",
      external_id: "890101",
      name: "acme/billing-ledger",
      organization: "acme",
      default_branch: "main",
      visibility: "private",
      mode: "approval",
      paused: false,
      policy_revision: 4,
      tags: ["tier-1", "python"],
      archived: false,
      is_fork: false,
      workflow_hazard_status: "clean",
      workflow_hazards: [],
      auto_repair_blocked: false,
      active: true,
      grant_review_required: false,
      sync_status: "ok",
      last_synced_at: NOW_ISO,
      last_ci_conclusion: "failure",
      last_ci_at: NOW_ISO,
    },
    {
      id: REPO_CHECKOUT_ID,
      workspace_id: WS_ID,
      version: 2,
      created_at: "2026-10-28T11:00:00Z",
      updated_at: NOW_ISO,
      connection_id: "0196f000-0000-7000-8000-000000000501",
      provider: "github",
      external_id: "890102",
      name: "acme/checkout-service",
      organization: "acme",
      default_branch: "main",
      visibility: "private",
      mode: "auto_repair",
      paused: false,
      policy_revision: 3,
      tags: ["tier-2", "typescript"],
      archived: false,
      is_fork: false,
      workflow_hazard_status: "clean",
      workflow_hazards: [],
      auto_repair_blocked: false,
      active: true,
      grant_review_required: false,
      sync_status: "ok",
      last_synced_at: NOW_ISO,
      last_ci_conclusion: "success",
      last_ci_at: NOW_ISO,
    },
    {
      id: REPO_PIPELINES_ID,
      workspace_id: WS_ID,
      version: 1,
      created_at: "2026-10-29T14:10:00Z",
      updated_at: NOW_ISO,
      connection_id: "0196f000-0000-7000-8000-000000000502",
      provider: "gitlab",
      external_id: "44109",
      name: "acme/release-workflows",
      organization: "acme",
      default_branch: "main",
      visibility: "private",
      mode: "monitor",
      paused: false,
      policy_revision: 1,
      tags: ["ci-infra"],
      archived: false,
      is_fork: false,
      workflow_hazard_status: "flagged",
      workflow_hazards: [
        {
          code: "pull_request_target_untrusted_checkout",
          severity: "critical",
          workflow_path: ".github/workflows/pr-target.yml",
          detail: "Untrusted PR head checkout inside pull_request_target blocks autonomous repair.",
        },
      ],
      auto_repair_blocked: true,
      active: true,
      grant_review_required: false,
      sync_status: "ok",
      last_synced_at: NOW_ISO,
      last_ci_conclusion: "failure",
      last_ci_at: NOW_ISO,
    },
  ],
  next_cursor: null,
  facets: {
    paused_count: 0,
    hazard_flagged_count: 1,
    partial_sync_connection_ids: [],
    providers: { github: 2, gitlab: 1 },
    modes: { monitor: 1, approval: 1, auto_repair: 1 },
    hazards: { clean: 2, flagged: 1, unscanned: 0 },
    tags: ["tier-1", "tier-2", "python", "typescript", "ci-infra"],
  },
};

const repairPayload = {
  id: REPAIR_ID,
  workspace_id: WS_ID,
  repository_id: REPO_BILLING_ID,
  run_id: RUN_ID,
  state: "policy_gate",
  proof_grade: "locally_verified",
  remote_status: "not_published",
  policy_revision: 4,
  base_sha: "7c4e91f2a8b034d19e5c62a18f07b3c4d91e20a5",
  target_ref: "refs/heads/main",
  parent_id: null,
  suspension: null,
  budget_id: "0196f000-0000-7000-8000-000000000755",
  version: 4,
  created_at: "2026-11-03T09:12:00Z",
  updated_at: NOW_ISO,
};

const diagnosisPayload = {
  items: [
    {
      id: "0196f000-0000-7000-8000-000000000211",
      class: "code_regression",
      decision: "continue",
      summary:
        "Meta Muse Spark localized a deterministic Decimal banker's-rounding regression in src/billing/proration.py introduced at commit 7c4e91f2a8b0: multi-seat credit notes quantize with ROUND_HALF_EVEN before tax aggregation instead of ROUND_HALF_UP, causing tests/test_proration.py::test_credit_note_subcent_Carry to fail with a $0.01 delta.",
      uncertainties: [
        "Verify downstream invoice CSV export snapshot fixtures remain unchanged when restoring ROUND_HALF_UP in proration line items.",
      ],
    },
  ],
  next_cursor: null,
  snapshot_at: NOW_ISO,
};

const patchesPayload = {
  items: [
    {
      id: "0196f000-0000-7000-8000-000000000221",
      attempt: 1,
      base_sha: "7c4e91f2a8b034d19e5c62a18f07b3c4d91e20a5",
      patch_digest: "9b4f18e20a71c53d8f02b46a9e12d7c438a105f9c2e8b4710d6a3f59e1b82c40",
      changed_paths: ["src/billing/proration.py"],
      diff_artifact_id: null,
    },
  ],
  next_cursor: null,
  snapshot_at: NOW_ISO,
};

const verificationPayload = {
  items: [
    {
      id: "0196f000-0000-7000-8000-000000000231",
      status: "verified",
      proof_grade: "locally_verified",
      patch_digest: "9b4f18e20a71c53d8f02b46a9e12d7c438a105f9c2e8b4710d6a3f59e1b82c40",
      gates: [
        { id: "V-01 (Baseline Red Repro)", outcome: "passed", evidence_ids: ["ev-repro-a"] },
        { id: "V-02 (Patched Target Green)", outcome: "passed", evidence_ids: ["ev-repro-b"] },
        { id: "V-03 (Broader Regression Suite)", outcome: "passed", evidence_ids: ["ev-suite-1", "ev-suite-2"] },
        { id: "V-04 (Static Lint & Typecheck)", outcome: "passed", evidence_ids: ["ev-lint-1"] },
        { id: "V-05 (Policy & Protected Path Diff Check)", outcome: "passed", evidence_ids: ["ev-pol-1"] },
        { id: "V-06 (No Test Deletion / Weakening Guard)", outcome: "passed", evidence_ids: ["ev-ast-1"] },
        { id: "V-07 (Signed Evidence Manifest V1)", outcome: "passed", evidence_ids: ["ev-sig-1"] },
      ],
    },
  ],
  reproductions: [
    {
      id: "0196f000-0000-7000-8000-000000000241",
      phase: "baseline_a",
      status: "repro_confirmed",
      base_sha: "7c4e91f2a8b034d19e5c62a18f07b3c4d91e20a5",
      patch_digest: null,
      fidelity_grade: "F1_TARGETED",
      executed_tests_count: 48,
      passed_tests_count: 47,
      failed_tests_count: 1,
      skipped_tests_count: 0,
      exit_code: 1,
      failure_reason_code: null,
    },
    {
      id: "0196f000-0000-7000-8000-000000000242",
      phase: "patched_b",
      status: "target_passed",
      base_sha: "7c4e91f2a8b034d19e5c62a18f07b3c4d91e20a5",
      patch_digest: "9b4f18e20a71c53d8f02b46a9e12d7c438a105f9c2e8b4710d6a3f59e1b82c40",
      fidelity_grade: "F2_BROADER",
      executed_tests_count: 184,
      passed_tests_count: 184,
      failed_tests_count: 0,
      skipped_tests_count: 0,
      exit_code: 0,
      failure_reason_code: null,
    },
  ],
  next_cursor: null,
  snapshot_at: NOW_ISO,
};

const timelinePayload = {
  items: [
    {
      id: "ev-1",
      at: "2026-11-03T09:12:04Z",
      source: "orchestrator",
      type: "repair.diagnosis.completed",
      reason_code: "code_regression",
    },
    {
      id: "ev-2",
      at: "2026-11-03T09:16:29Z",
      source: "verifier",
      type: "repair.verification.locally_verified",
      reason_code: "all_local_gates_passed",
    },
  ],
  next_cursor: null,
  snapshot_at: NOW_ISO,
};

const publicationPrimary = {
  id: PUBLICATION_ID,
  version: 2,
  workspace_id: WS_ID,
  repository_id: REPO_BILLING_ID,
  repair_id: REPAIR_ID,
  intent_id: "0196f000-0000-7000-8000-000000000901",
  branch: "red2pr/repair/0196f000-proration-rounding",
  expected_commit_sha: "4e82d910a7f5c31b6d08e294a1c7f5038b9d21e6",
  provider_object_id: "pr-418",
  url: "https://github.com/acme/billing-ledger/pull/418",
  status: "published",
  created_at: "2026-11-03T09:20:00Z",
  updated_at: NOW_ISO,
};

const publicationSecondary = {
  id: PUBLICATION_SECOND_ID,
  version: 1,
  workspace_id: WS_ID,
  repository_id: REPO_CHECKOUT_ID,
  repair_id: "0196f000-0000-7000-8000-000000000202",
  intent_id: "0196f000-0000-7000-8000-000000000902",
  branch: "red2pr/repair/0196f002-cart-null-guard",
  expected_commit_sha: "81a3f07c5b29e410d6c82a91f40e73b5c19d82a4",
  provider_object_id: "pr-192",
  url: "https://github.com/acme/checkout-service/pull/192",
  status: "published",
  created_at: "2026-11-02T17:40:00Z",
  updated_at: "2026-11-02T17:48:00Z",
};

const remoteCheckPrimary = {
  id: "0196f000-0000-7000-8000-000000000911",
  version: 2,
  workspace_id: WS_ID,
  repository_id: REPO_BILLING_ID,
  publication_id: PUBLICATION_ID,
  head_sha: "4e82d910a7f5c31b6d08e294a1c7f5038b9d21e6",
  expected_check_set_digest: "c3a91e5078f24d16b80e95a3c712d4f860b39e17a54c82d09f1b6e37a4c810d2",
  required_check_names: ["unit-tests", "mypy-strict", "security-gate"],
  observations: [
    {
      check_name: "unit-tests",
      external_id: "gh-check-9001",
      head_sha: "4e82d910a7f5c31b6d08e294a1c7f5038b9d21e6",
      status: "completed",
      conclusion: "success",
      observed_at: NOW_ISO,
    },
    {
      check_name: "mypy-strict",
      external_id: "gh-check-9002",
      head_sha: "4e82d910a7f5c31b6d08e294a1c7f5038b9d21e6",
      status: "completed",
      conclusion: "success",
      observed_at: NOW_ISO,
    },
    {
      check_name: "security-gate",
      external_id: "gh-check-9003",
      head_sha: "4e82d910a7f5c31b6d08e294a1c7f5038b9d21e6",
      status: "completed",
      conclusion: "success",
      observed_at: NOW_ISO,
    },
  ],
  outcome: "passed",
  created_at: "2026-11-03T09:21:00Z",
  updated_at: NOW_ISO,
};

function createSpaServer() {
  const indexHtml = path.join(distDir, "index.html");
  assert.ok(fs.existsSync(indexHtml), `Missing built SPA bundle at ${indexHtml}`);
  return http.createServer((req, res) => {
    const reqPath = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    const rel = reqPath.replace(/^\/+/, "");
    const candidate = path.resolve(distDir, rel);
    if (
      rel &&
      candidate.startsWith(distDir + path.sep) &&
      fs.existsSync(candidate) &&
      fs.statSync(candidate).isFile()
    ) {
      const ext = path.extname(candidate).toLowerCase();
      res.writeHead(200, { "Content-Type": MIME_TYPES[ext] ?? "application/octet-stream" });
      fs.createReadStream(candidate).pipe(res);
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    fs.createReadStream(indexHtml).pipe(res);
  });
}

async function captureScreen(browser, baseUrl, spec, colorScheme) {
  const context = await browser.newContext({
    viewport: { width: 1360, height: spec.height ?? 860 },
    deviceScaleFactor: 2,
    colorScheme,
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));

  await page.addInitScript((mode) => {
    void mode;
    window.localStorage.clear();
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const url = new URL(
        typeof input === "string"
          ? input
          : input instanceof Request
            ? input.url
            : String(input),
        window.location.href,
      );
      if (url.pathname.endsWith("/events")) {
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode(": connected\n\n"));
            },
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "text/event-stream; charset=utf-8",
              "Cache-Control": "no-cache",
            },
          },
        );
      }
      return nativeFetch(input, init);
    };
  }, colorScheme);

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== baseUrl) {
      await route.abort();
      return;
    }
    if (!url.pathname.startsWith("/api/v1/")) {
      await route.continue();
      return;
    }
    const p = url.pathname;
    const headers = { "X-Correlation-Id": "corr-readme-preview" };
    if (p === "/api/v1/me") {
      await route.fulfill({ json: mePayload, headers });
    } else if (p === "/api/v1/setup") {
      await route.fulfill({ json: setupCompleted, headers });
    } else if (p === "/api/v1/workspaces/acme") {
      await route.fulfill({ json: workspace, headers });
    } else if (p === "/api/v1/workspaces/acme/analytics") {
      await route.fulfill({ json: analyticsPayload, headers });
    } else if (p === "/api/v1/workspaces/acme/repositories") {
      await route.fulfill({ json: repositoriesPayload, headers });
    } else if (p === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}`) {
      await route.fulfill({ json: repairPayload, headers });
    } else if (p === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}/diagnosis`) {
      await route.fulfill({ json: diagnosisPayload, headers });
    } else if (p === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}/patches`) {
      await route.fulfill({ json: patchesPayload, headers });
    } else if (p === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}/verification`) {
      await route.fulfill({ json: verificationPayload, headers });
    } else if (p === `/api/v1/workspaces/acme/repairs/${REPAIR_ID}/timeline`) {
      await route.fulfill({ json: timelinePayload, headers });
    } else if (p === "/api/v1/workspaces/acme/publications") {
      await route.fulfill({
        json: {
          items: [publicationPrimary, publicationSecondary],
          next_cursor: null,
          snapshot_at: NOW_ISO,
        },
        headers,
      });
    } else if (p === `/api/v1/workspaces/acme/publications/${PUBLICATION_ID}`) {
      await route.fulfill({
        json: { publication: publicationPrimary, remote_check: remoteCheckPrimary },
        headers,
      });
    } else {
      await route.fulfill({
        status: 404,
        json: { detail: `Unmapped preview endpoint: ${p}` },
        headers,
      });
    }
  });

  await page.goto(`${baseUrl}${spec.route}`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { level: 1, name: spec.heading }).waitFor({ state: "visible" });
  if (spec.prepare) {
    await spec.prepare(page);
  }

  await page.addScriptTag({ path: axeScriptPath });
  const axe = await page.evaluate(async () => window.axe.run(document));
  const bounds = await page.evaluate(() => ({
    width: window.innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
    theme: document.documentElement.dataset.theme,
  }));
  assert.equal(bounds.theme, colorScheme, `${spec.name}: theme mismatch (${bounds.theme})`);
  assert.ok(
    bounds.scrollWidth <= bounds.width,
    `${spec.name} (${colorScheme}): horizontal overflow ${bounds.scrollWidth} > ${bounds.width}`,
  );
  assert.deepEqual(errors, [], `${spec.name} (${colorScheme}): runtime errors ${errors.join("; ")}`);
  assert.deepEqual(
    axe.violations.map((v) => v.id),
    [],
    `${spec.name} (${colorScheme}): axe violations`,
  );

  const outFile = path.join(outputDir, `${spec.name}-${colorScheme}.png`);
  await page.screenshot({ path: outFile, fullPage: Boolean(spec.fullPage) });
  await context.close();
  const sizeKb = Math.round(fs.statSync(outFile).size / 1024);
  return { file: path.relative(repoRoot, outFile), sizeKb, theme: bounds.theme };
}

(async () => {
  fs.mkdirSync(outputDir, { recursive: true });
  const server = createSpaServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const screens = [
    {
      name: "hero-overview",
      route: "/w/acme/overview",
      heading: "Workspace overview",
      height: 1120,
      fullPage: true,
      prepare: async (page) => {
        await page.getByText("42", { exact: false }).first().waitFor({ state: "visible" });
      },
    },
    {
      name: "repositories",
      route: "/w/acme/repositories",
      heading: "Repository Catalog & Safety Posture",
      fullPage: false,
      prepare: async (page) => {
        await page.getByText("acme/billing-ledger").waitFor({ state: "visible" });
      },
    },
    {
      name: "repair-diagnosis",
      route: `/w/acme/repairs/${REPAIR_ID}`,
      heading: /^Repair /,
      fullPage: false,
      prepare: async (page) => {
        await page.getByText(/Meta Muse Spark localized/i).waitFor({ state: "visible" });
      },
    },
    {
      name: "verification-proof",
      route: `/w/acme/repairs/${REPAIR_ID}`,
      heading: /^Repair /,
      fullPage: false,
      prepare: async (page) => {
        await page.getByRole("tab", { name: "Verification" }).click();
        await page.getByText("Deterministic verification").waitFor({ state: "visible" });
      },
    },
    {
      name: "draft-pr-workflow",
      route: "/w/acme/prs",
      heading: "Pull requests",
      height: 1020,
      fullPage: true,
      prepare: async (page) => {
        await page.getByRole("button", { name: /published · 0196f000/i }).click();
        await page.getByText("Publication details").waitFor({ state: "visible" });
        await page.getByText("passed on exact SHA").first().waitFor({ state: "visible" });
      },
    },
  ];

  const browser = await chromium.launch({ headless: true, executablePath: browserPath });
  try {
    const results = [];
    for (const spec of screens) {
      for (const scheme of ["light", "dark"]) {
        results.push(await captureScreen(browser, baseUrl, spec, scheme));
      }
    }
    console.log(JSON.stringify(results, null, 2));
  } finally {
    await browser.close();
    server.close();
  }
})();
