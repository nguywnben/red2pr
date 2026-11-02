const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");

const { chromium } = require(path.resolve(
  __dirname,
  "../../../build/browser-tools/node_modules/playwright-core",
));

const baseUrl = process.env.RED2PR_PREVIEW_URL ?? "http://127.0.0.1:5182";
const suffix = process.argv[2] ?? "after";
const outputDirectory = __dirname;
const edgePath = process.env.RED2PR_BROWSER_EXECUTABLE ??
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

function safeFileName(name) {
  return name.toLowerCase().replace(/[^a-z0-9-]+/g, "-");
}

async function inspect(page, label) {
  const result = await page.evaluate((stateLabel) => {
    const activeInput = document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
    const input = activeInput ?? document.querySelector("input");
    const link = [...document.querySelectorAll("a")].find((element) =>
      element.textContent?.includes("Use a recovery code"),
    );
    const chain = (element) => {
      const items = [];
      let current = element;
      while (current && items.length < 5) {
        items.push({ tag: current.tagName.toLowerCase(), className: current.className });
        current = current.parentElement;
      }
      return items;
    };
    const styles = (element) => {
      if (!element) return null;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return {
        tag: element.tagName.toLowerCase(),
        className: element.className,
        width: Math.round(rect.width * 100) / 100,
        height: Math.round(rect.height * 100) / 100,
        display: style.display,
        backgroundColor: style.backgroundColor,
        backgroundImage: style.backgroundImage,
        border: `${style.borderTopWidth} ${style.borderTopStyle} ${style.borderTopColor}`,
        borderRadius: style.borderRadius,
        boxShadow: style.boxShadow,
        outline: `${style.outlineWidth} ${style.outlineStyle} ${style.outlineColor}`,
        outlineOffset: style.outlineOffset,
        color: style.color,
        textDecoration: style.textDecorationLine,
        focused: element.matches(":focus"),
        focusVisible: element.matches(":focus-visible"),
        hovered: element.matches(":hover"),
        active: element.matches(":active"),
      };
    };
    const inputWrapper = input?.parentElement ?? null;
    const active = document.activeElement;
    return {
      label: stateLabel,
      theme: document.documentElement.getAttribute("data-theme"),
      activeElement: active ? {
        tag: active.tagName.toLowerCase(),
        className: active.className,
        text: active.textContent?.trim().slice(0, 70),
      } : null,
      inputAncestorChain: chain(input),
      input: styles(input),
      inputWrapper: styles(inputWrapper),
      link: styles(link),
      linkAncestorChain: chain(link),
      selectionText: document.getSelection()?.toString() ?? "",
      linkSelectionBackground: link ? getComputedStyle(link, "::selection").backgroundColor : null,
      themeTokens: {
        focusColor: getComputedStyle(document.documentElement).getPropertyValue("--focus-outline-color").trim(),
        accentColor: getComputedStyle(document.documentElement).getPropertyValue("--color-accent").trim(),
        pressedOverlay: getComputedStyle(document.documentElement).getPropertyValue("--color-overlay-pressed").trim(),
        legacyFocusColor: getComputedStyle(document.documentElement).getPropertyValue("--red2pr-focus-ring").trim(),
      },
    };
  }, label);
  return result;
}

async function capture(page, name) {
  await page.screenshot({
    path: path.join(outputDirectory, `${safeFileName(name)}-${suffix}.png`),
    fullPage: true,
  });
}

function stateFor(states, suffix) {
  const state = states.find((item) => item.label.endsWith(suffix));
  assert.ok(state, `Missing browser state: ${suffix}`);
  return state;
}

function hasVisibleInsetRing(boxShadow) {
  const match = boxShadow.match(/0px 0px 0px\s+([0-9.]+)px inset/);
  return match !== null && Number(match[1]) >= 0.5;
}

function verifyInteractionStates(theme, states, tabTrace, consoleErrors) {
  assert.equal(stateFor(states, "idle").themeTokens.legacyFocusColor, "", `${theme}: legacy focus token must not be defined`);
  const pointerInputs = states.filter((state) => state.label.includes("pointer focused input "));
  assert.ok(pointerInputs.length > 0, `${theme}: pointer checks should cover every TextInput`);
  for (const pointerInput of pointerInputs) {
    assert.equal(pointerInput.input.focused, true, `${theme}: pointer click should focus ${pointerInput.label}`);
    assert.match(pointerInput.input.outline, /\bnone\b/, `${theme}: Astryx should own the TextInput focus treatment`);
    assert.ok(hasVisibleInsetRing(pointerInput.inputWrapper.boxShadow), `${theme}: pointer-focused TextInput should retain its Astryx focus treatment`);
  }

  const keyboardInputs = states.filter((state) => state.label.endsWith("keyboard focused input"));
  assert.ok(keyboardInputs.length > 0, `${theme}: Tab should focus a TextInput`);
  assert.ok(keyboardInputs.length > 0, `${theme}: Tab should focus a TextInput`);
  assert.ok(keyboardInputs.every((state) => state.input.focusVisible && hasVisibleInsetRing(state.inputWrapper.boxShadow)), `${theme}: every keyboard-focused TextInput needs a visible component focus treatment`);

  const hover = stateFor(states, "hovered recovery link");
  assert.equal(hover.link.hovered, true, `${theme}: hover state should be measurable`);
  assert.equal(hover.link.textDecoration, "underline", `${theme}: hover should underline the recovery link`);

  const selected = stateFor(states, "recovery text selected");
  assert.equal(selected.selectionText, "Can't sign in? Use a recovery code", `${theme}: text selection must be recorded separately from focus`);

  const active = stateFor(states, "active recovery link");
  assert.equal(active.link.active, true, `${theme}: pointer down should expose :active`);
  assert.ok(active.link.width < active.inputWrapper.width, `${theme}: Recovery link should remain content-sized instead of stretching across the card`);
  assert.equal(active.link.backgroundColor, "rgba(0, 0, 0, 0)", `${theme}: pressing the recovery link must not paint a wide gray background`);

  const pointerLink = stateFor(states, "pointer focused recovery link");
  assert.equal(pointerLink.link.focused, true, `${theme}: pointer activation should focus the link`);
  assert.equal(pointerLink.link.focusVisible, false, `${theme}: pointer focus should not show the keyboard focus ring`);

  const keyboardLink = stateFor(states, "keyboard focused recovery link");
  assert.equal(keyboardLink.link.focusVisible, true, `${theme}: Tab should make the link focus-visible`);
  assert.match(keyboardLink.link.outline, /^2px solid /, `${theme}: Astryx keyboard ring should be visible`);
  assert.equal(keyboardLink.link.outlineOffset, "3px", `${theme}: keyboard ring should use Astryx focus offset token`);

  const blurred = stateFor(states, "recovery link blurred by pointer");
  assert.equal(blurred.link.focused, false, `${theme}: pointer blur should clear focus`);
  assert.deepEqual(consoleErrors, [], `${theme}: browser page should not report runtime errors`);
  assert.ok(tabTrace.some((item) => item?.focusVisible), `${theme}: keyboard Tab trace should include a focus-visible target`);
}

async function checkTheme(browser, theme) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  await page.emulateMedia({ colorScheme: theme });
  const consoleErrors = [];
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });
  const input = page.locator("input").first();
  const link = page.getByRole("link", { name: /recovery code/i });
  await input.waitFor({ state: "visible" });
  await link.waitFor({ state: "visible" });

  const states = [];
  states.push(await inspect(page, `${theme}: idle`));

  const inputCount = await page.locator("input").count();
  for (let index = 0; index < inputCount; index += 1) {
    await page.locator("input").nth(index).click();
    await page.waitForTimeout(250);
    states.push(await inspect(page, `${theme}: pointer focused input ${index + 1}`));
    await capture(page, `login-input-pointer-${theme}-${index + 1}`);
  }

  await page.locator("h1").click({ position: { x: 5, y: 5 } });
  await page.waitForTimeout(250);
  states.push(await inspect(page, `${theme}: input blurred by pointer`));
  await capture(page, `login-input-blur-${theme}`);

  await link.hover();
  await page.waitForTimeout(250);
  states.push(await inspect(page, `${theme}: hovered recovery link`));
  await capture(page, `login-recovery-hover-${theme}`);

  await link.evaluate((element) => {
    const range = document.createRange();
    range.selectNodeContents(element);
    const selection = document.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
  });
  states.push(await inspect(page, `${theme}: recovery text selected`));
  await capture(page, `login-recovery-selection-${theme}`);
  await page.evaluate(() => document.getSelection()?.removeAllRanges());

  await link.evaluate((element) => {
    element.addEventListener("click", (event) => event.preventDefault(), { once: true });
  });
  const linkBox = await link.boundingBox();
  if (!linkBox) throw new Error("Recovery link has no visible box");
  await page.mouse.move(linkBox.x + Math.min(8, linkBox.width / 2), linkBox.y + linkBox.height / 2);
  await page.mouse.down();
  states.push(await inspect(page, `${theme}: active recovery link`));
  await capture(page, `login-recovery-active-${theme}`);
  await page.mouse.up();
  await page.waitForTimeout(250);
  states.push(await inspect(page, `${theme}: pointer focused recovery link`));
  await capture(page, `login-recovery-pointer-focus-${theme}`);
  await page.locator("h1").click({ position: { x: 5, y: 5 } });
  await page.waitForTimeout(250);
  states.push(await inspect(page, `${theme}: recovery link blurred by pointer`));
  await capture(page, `login-recovery-blur-${theme}`);

  await page.reload({ waitUntil: "domcontentloaded" });
  await input.waitFor({ state: "visible" });
  const tabTrace = [];
  for (let index = 0; index < 7; index += 1) {
    await page.keyboard.press("Tab");
    await page.waitForTimeout(250);
    tabTrace.push(await page.evaluate(() => {
      const active = document.activeElement;
      return active ? {
        tag: active.tagName.toLowerCase(),
        className: active.className,
        text: active.textContent?.trim().slice(0, 70),
        focusVisible: active.matches(":focus-visible"),
      } : null;
    }));
    const active = await page.evaluate(() => document.activeElement?.tagName.toLowerCase());
    if (active === "input") {
      states.push(await inspect(page, `${theme}: keyboard focused input`));
      await capture(page, `login-input-keyboard-${theme}`);
    }
    if (await link.evaluate((element) => element === document.activeElement).catch(() => false)) {
      states.push(await inspect(page, `${theme}: keyboard focused recovery link`));
      await capture(page, `login-recovery-keyboard-${theme}`);
      break;
    }
  }

  await page.evaluate(() => document.activeElement?.blur());
  await page.keyboard.press("Tab");
  const finalActive = await inspect(page, `${theme}: first keyboard stop`);

  verifyInteractionStates(theme, states, tabTrace, consoleErrors);

  await page.close();
  return { theme, states, tabTrace, finalActive, consoleErrors };
}

(async () => {
  fs.mkdirSync(outputDirectory, { recursive: true });
  const browser = await chromium.launch({
    executablePath: edgePath,
    headless: true,
    args: ["--disable-crash-reporter", "--disable-breakpad", "--disable-background-networking"],
  });
  try {
    const results = [];
    results.push(await checkTheme(browser, "light"));
    results.push(await checkTheme(browser, "dark"));
    fs.writeFileSync(
      path.join(outputDirectory, `focus-states-${suffix}.json`),
      `${JSON.stringify(results, null, 2)}\n`,
    );
    const concise = results.map((themeResult) => ({
      theme: themeResult.theme,
      pointerInputs: themeResult.states.filter((state) => state.label.includes("pointer focused input ")).map((state) => ({
        label: state.label,
        focused: state.input.focused,
        focusVisible: state.input.focusVisible,
        nativeOutline: state.input.outline,
        AstryxWrapperBorder: state.inputWrapper.border,
        AstryxWrapperFocusShadow: state.inputWrapper.boxShadow,
      })),
      keyboardInputs: themeResult.states.filter((state) => state.label.endsWith("keyboard focused input")).map((state) => ({
        focused: state.input.focused,
        focusVisible: state.input.focusVisible,
        AstryxWrapperFocusShadow: state.inputWrapper.boxShadow,
      })),
      recoveryHover: stateFor(themeResult.states, "hovered recovery link").link.textDecoration,
      recoveryPress: {
        width: stateFor(themeResult.states, "active recovery link").link.width,
        background: stateFor(themeResult.states, "active recovery link").link.backgroundColor,
      },
      recoveryPointerFocusVisible: stateFor(themeResult.states, "pointer focused recovery link").link.focusVisible,
      recoveryKeyboardFocus: stateFor(themeResult.states, "keyboard focused recovery link").link.outline,
      selectionText: stateFor(themeResult.states, "recovery text selected").selectionText,
      tabTrace: themeResult.tabTrace.map((item) => ({ tag: item.tag, text: item.text, focusVisible: item.focusVisible })),
      consoleErrors: themeResult.consoleErrors,
    }));
    process.stdout.write(`${JSON.stringify(concise, null, 2)}\n`);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  process.stderr.write(`${error.stack ?? error}\n`);
  process.exitCode = 1;
});
