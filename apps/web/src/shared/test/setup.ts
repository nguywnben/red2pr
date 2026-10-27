import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});

// Deterministic CSS.escape polyfill for environments missing full CSSOM escape
if (typeof globalThis.CSS === "undefined") {
  Object.defineProperty(globalThis, "CSS", {
    configurable: true,
    writable: true,
    value: {},
  });
}
if (typeof globalThis.CSS.escape !== "function") {
  globalThis.CSS.escape = (value: string): string =>
    String(value).replace(/[^a-zA-Z0-9_-]/g, (ch) => `\\${ch}`);
}

// Deterministic matchMedia shim for responsive & reduced-motion / system-theme tests
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string): MediaQueryList => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }),
  });
}

// Deterministic ResizeObserver shim for Astryx AppShell / Table & virtualizers in jsdom
if (typeof globalThis.ResizeObserver === "undefined") {
  class ResizeObserverShim implements ResizeObserver {
    private readonly callback: ResizeObserverCallback;

    public constructor(callback: ResizeObserverCallback) {
      this.callback = callback;
    }

    public observe(target: Element): void {
      const rect = target.getBoundingClientRect();
      const width = rect.width > 0 ? rect.width : 1280;
      const height = rect.height > 0 ? rect.height : 720;
      const size: ResizeObserverSize = { inlineSize: width, blockSize: height };
      this.callback(
        [
          {
            target,
            contentRect: {
              x: 0,
              y: 0,
              width,
              height,
              top: 0,
              left: 0,
              bottom: height,
              right: width,
              toJSON: () => ({}),
            } as DOMRectReadOnly,
            borderBoxSize: [size],
            contentBoxSize: [size],
            devicePixelContentBoxSize: [size],
          },
        ],
        this,
      );
    }

    public unobserve(): void {
      return undefined;
    }

    public disconnect(): void {
      return undefined;
    }
  }

  Object.defineProperty(globalThis, "ResizeObserver", {
    configurable: true,
    writable: true,
    value: ResizeObserverShim,
  });
}

// Native HTMLDialogElement showModal/close shims for jsdom
if (typeof HTMLDialogElement !== "undefined") {
  if (typeof HTMLDialogElement.prototype.showModal !== "function") {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement): void {
      this.setAttribute("open", "");
    };
  }
  if (typeof HTMLDialogElement.prototype.close !== "function") {
    HTMLDialogElement.prototype.close = function close(
      this: HTMLDialogElement,
      returnValue?: string,
    ): void {
      if (returnValue !== undefined) {
        this.returnValue = returnValue;
      }
      this.removeAttribute("open");
      this.dispatchEvent(new Event("close"));
    };
  }
}

if (typeof Element !== "undefined" && typeof Element.prototype.scrollIntoView !== "function") {
  Element.prototype.scrollIntoView = () => undefined;
}

if (typeof window !== "undefined") {
  window.scrollTo = () => undefined;
}

if (typeof HTMLCanvasElement !== "undefined") {
  HTMLCanvasElement.prototype.getContext = () => null;
}
