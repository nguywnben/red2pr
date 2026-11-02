const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");

const { chromium } = require(path.resolve(
  __dirname,
  "../../../build/browser-tools/node_modules/playwright-core",
));

const baseUrl = process.env.RED2PR_PREVIEW_URL ?? "http://127.0.0.1:5182";
const outputDirectory = __dirname;
const browserPath = process.env.RED2PR_BROWSER_EXECUTABLE ??
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const workspace = {
  id: "0196ef00-0000-7000-8000-000000000301",
  name: "Core workspace",
  slug: "core",
  status: "active",
};
const analytics = {
  workspace_id: workspace.id,
  range_start: "2026-10-01T00:00:00Z",
  range_end: "2026-10-30T23:59:59Z",
  repository_count: 2,
  funnel: [
    { key: "ingested", value: 5, numerator: null, denominator: null },
    { key: "eligible", value: 4, numerator: 4, denominator: 5 },
    { key: "executed", value: 3, numerator: 3, denominator: 4 },
    { key: "reproduced", value: 2, numerator: 2, denominator: 3 },
    { key: "locally_verified", value: 1, numerator: 1, denominator: 2 },
    { key: "publication_eligible", value: 1, numerator: 1, denominator: 1 },
    { key: "published_observed", value: 1, numerator: 1, denominator: 1 },
    { key: "remotely_verified", value: 0, numerator: 0, denominator: 1 },
  ],
  local_success_count: 1,
  remote_success_count: 0,
  unknown_count: 2,
  pending_count: 1,
  abstained_count: 1,
  costs: [{ currency: "USD", settled: "1.250000", estimated_unsettled: "0.500000", total: "1.750000", unknown_rows: 1, usage_rows: 4 }],
  watermark: "2026-10-30T10:00:00Z",
};

async function render(browser, pathName, colorScheme, viewport, suffix) {
  const page = await browser.newPage({ viewport });
  await page.emulateMedia({ colorScheme });
  const errors = [];
  const apiPaths = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const requestUrl = new URL(typeof input === "string" ? input : input instanceof Request ? input.url : input.toString(), window.location.href);
      if (requestUrl.pathname.endsWith("/events")) {
        return new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(": connected\n\n"));
          },
        }), { status: 200, headers: { "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache" } });
      }
      return nativeFetch(input, init);
    };
  });
  await page.route("**/*", async (route) => {
    const requestUrl = new URL(route.request().url());
    if (requestUrl.origin !== baseUrl) {
      await route.abort();
      return;
    }
    if (!requestUrl.pathname.startsWith("/api/v1/")) {
      await route.continue();
      return;
    }
    apiPaths.push(`${route.request().method()} ${requestUrl.pathname}`);
    if (requestUrl.pathname === "/api/v1/me") {
      await route.fulfill({ json: { is_instance_owner: true, mfa_enabled: true, step_up_valid_until: null, workspaces: [workspace] } });
    } else if (requestUrl.pathname === "/api/v1/workspaces/core") {
      await route.fulfill({ json: workspace });
    } else if (requestUrl.pathname.endsWith("/events")) {
      await route.fulfill({ status: 204, body: "" });
    } else if (requestUrl.pathname.endsWith("/analytics")) {
      await route.fulfill({ json: analytics });
    } else if (requestUrl.pathname === "/api/v1/system/status") {
      await route.fulfill({ json: { state: "ready", generated_at: "2026-10-31T00:00:00Z", application_version: "0.1.0", schema_revision: "0025_mcp_intents", database_version: "16.4", recovery_epoch: 1, maintenance_enabled: false, maintenance_reason: null, worker_protocols: [], checks: [{ check_id: "database", state: "ok", summary: "PostgreSQL is reachable." }] } });
    } else if (requestUrl.pathname === "/api/v1/system/doctor") {
      await route.fulfill({ json: { generated_at: "2026-10-31T00:00:00Z", overall_state: "healthy", checks: [{ check_id: "database", state: "ok", summary: "Database is reachable." }] } });
    } else {
      await route.fulfill({ status: 404, json: { detail: "No fixture registered for this browser preview request." } });
    }
  });

  await page.goto(`${baseUrl}${pathName}`, { waitUntil: "domcontentloaded" });
  const expectedHeading = pathName === "/system" ? "System operations" : pathName.endsWith("/analytics") ? "Analytics and cost ledger" : "Workspace overview";
  await page.getByRole("heading", { level: 1, name: expectedHeading }).waitFor({ state: "visible" });
  await page.addScriptTag({ path: path.resolve(__dirname, "../../../apps/web/node_modules/axe-core/axe.min.js") });
  const axe = await page.evaluate(async () => window.axe.run(document));
  const bounds = await page.evaluate(() => ({ width: window.innerWidth, documentWidth: document.documentElement.scrollWidth, theme: document.documentElement.dataset.theme }));
  const navigationGeometry = viewport.width <= 400
    ? await page.evaluate(() => [...document.querySelectorAll('[role="navigation"]')].map((element) => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        label: element.getAttribute("aria-label"),
        className: element.className,
        width: rect.width,
        height: rect.height,
        scrollWidth: element.scrollWidth,
        clientWidth: element.clientWidth,
        display: style.display,
        children: [...element.children].map((child) => {
          const childRect = child.getBoundingClientRect();
          return { text: child.textContent?.trim().slice(0, 60), className: child.className, x: childRect.x, y: childRect.y, width: childRect.width, height: childRect.height, scrollWidth: child.scrollWidth };
        }),
        controls: [...element.querySelectorAll("a, button")].map((control) => {
          const rect = control.getBoundingClientRect();
          return {
            name: control.getAttribute("aria-label") ?? control.textContent?.trim().replace(/\s+/g, " ").slice(0, 40),
            x: rect.x,
            y: rect.y,
            right: rect.right,
            bottom: rect.bottom,
            width: rect.width,
            height: rect.height,
            visible: rect.width > 0 && rect.height > 0,
          };
        }),
      };
    }))
    : [];
  const tableGeometry = await page.evaluate(() => [...document.querySelectorAll('[role="group"]')]
    .filter((element) => element.querySelector("table"))
    .map((element) => ({
      label: element.getAttribute("aria-label"),
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
      tableWidth: element.querySelector("table")?.getBoundingClientRect().width ?? 0,
    })));
  assert.ok(bounds.documentWidth <= bounds.width, `${pathName} ${colorScheme} ${viewport.width}px: horizontal overflow ${bounds.documentWidth}px`);
  assert.deepEqual(errors, [], `${pathName} ${colorScheme}: browser runtime errors`);
  assert.deepEqual(axe.violations, [], `${pathName} ${colorScheme}: axe violations`);
  for (const nav of navigationGeometry) {
    assert.ok(nav.controls.every((control) => control.visible), `${pathName} ${viewport.width}px: a top navigation control is hidden`);
    assert.ok(nav.controls.every((control) => control.x >= 0 && control.right <= viewport.width), `${pathName} ${viewport.width}px: a top navigation control is outside the viewport`);
    for (let first = 0; first < nav.controls.length; first += 1) {
      for (let second = first + 1; second < nav.controls.length; second += 1) {
        const a = nav.controls[first];
        const b = nav.controls[second];
        const overlaps = a.x < b.right && a.right > b.x && a.y < b.bottom && a.bottom > b.y;
        assert.ok(!overlaps, `${pathName} ${viewport.width}px: top navigation controls overlap (${a.name}, ${b.name})`);
      }
    }
  }
  await page.screenshot({ path: path.join(outputDirectory, `${suffix}.png`), fullPage: true });
  await page.close();
  return { pathName, colorScheme, viewport, ...bounds, navigationGeometry, tableGeometry, axeViolations: axe.violations.length, apiPaths: [...new Set(apiPaths)], errors };
}

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: browserPath });
  try {
    const results = [];
    results.push(await render(browser, "/w/core/overview", "light", { width: 1440, height: 960 }, "overview-light-desktop-final"));
    results.push(await render(browser, "/w/core/overview", "dark", { width: 1440, height: 960 }, "overview-dark-desktop-final"));
    results.push(await render(browser, "/w/core/overview", "light", { width: 390, height: 844 }, "overview-light-mobile-final"));
    results.push(await render(browser, "/w/core/overview", "light", { width: 320, height: 800 }, "overview-light-mobile-320-final"));
    results.push(await render(browser, "/w/core/analytics", "light", { width: 1280, height: 900 }, "analytics-light-desktop-final"));
    results.push(await render(browser, "/w/core/analytics", "light", { width: 390, height: 844 }, "analytics-light-mobile-final"));
    results.push(await render(browser, "/system", "light", { width: 1280, height: 900 }, "system-light-desktop-final"));
    fs.writeFileSync(path.join(outputDirectory, "ui-shell-preview-final.json"), `${JSON.stringify(results, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
