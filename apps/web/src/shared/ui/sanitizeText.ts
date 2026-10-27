/**
 * SEC-040 untrusted text & URL sanitization utilities for CI logs, patch diffs,
 * and external links rendered in the Red2PR web UI.
 */

// Matches ANSI CSI sequences: ESC [ params intermediates final
// eslint-disable-next-line no-control-regex
const ANSI_CSI_RE = /\u001b\[[0-?]*[ -/]*[@-~]/g;

// Matches ANSI OSC sequences (including OSC 52 clipboard & OSC 8 links) terminated by BEL or ST
// eslint-disable-next-line no-control-regex
const ANSI_OSC_RE = /\u001b\][\s\S]*?(?:\u0007|\u001b\\)/g;

// Matches DCS, SOS, PM, APC sequences terminated by BEL or ST
// eslint-disable-next-line no-control-regex
const ANSI_STRING_ESCAPE_RE = /\u001b[PX^_][\s\S]*?(?:\u0007|\u001b\\)/g;

// Matches remaining 2-byte ESC sequences and stray ESC bytes
// eslint-disable-next-line no-control-regex
const ANSI_SINGLE_ESC_RE = /\u001b[@-Z\\-_]?/g;

// Matches ASCII C0/C1 control characters except \n (0x0A) and \t (0x09)
// eslint-disable-next-line no-control-regex
const UNSAFE_CONTROL_CHARS_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

// Matches Trojan-Source Unicode bidirectional control characters (CVE-2021-42574)
const BIDI_OVERRIDE_RE = /[\u202a-\u202e\u2066-\u2069\u061c]/g;

export interface SanitizedTextResult {
  readonly text: string;
  readonly strippedSequences: number;
  readonly bidiCount: number;
}

export function sanitizeUntrustedText(raw: string): SanitizedTextResult {
  if (raw.length === 0) {
    return { text: "", strippedSequences: 0, bidiCount: 0 };
  }

  let strippedSequences = 0;
  let bidiCount = 0;

  let working = raw.replace(/\r\n?/g, "\n");

  const countAndStrip = (pattern: RegExp): void => {
    working = working.replace(pattern, () => {
      strippedSequences += 1;
      return "";
    });
  };

  countAndStrip(ANSI_OSC_RE);
  countAndStrip(ANSI_STRING_ESCAPE_RE);
  countAndStrip(ANSI_CSI_RE);
  countAndStrip(ANSI_SINGLE_ESC_RE);
  countAndStrip(UNSAFE_CONTROL_CHARS_RE);

  working = working.replace(BIDI_OVERRIDE_RE, () => {
    bidiCount += 1;
    strippedSequences += 1;
    return "[BIDI-STRIPPED]";
  });

  return {
    text: working,
    strippedSequences,
    bidiCount,
  };
}

export function sanitizeNavigationHref(rawHref: string | null | undefined): string | null {
  if (typeof rawHref !== "string") {
    return null;
  }
  const trimmed = rawHref.trim();
  if (trimmed.length === 0) {
    return null;
  }

  // Collapse whitespace and ASCII control bytes before inspecting protocol scheme (SEC-040)
  let compact = "";
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code > 0x20 && code !== 0x7f) {
      compact += trimmed[i];
    }
  }
  const lower = compact.toLowerCase();

  if (
    lower.startsWith("javascript:") ||
    lower.startsWith("data:") ||
    lower.startsWith("vbscript:") ||
    lower.startsWith("file:") ||
    lower.startsWith("blob:") ||
    lower.startsWith("//")
  ) {
    return null;
  }

  if (trimmed.startsWith("/") || trimmed.startsWith("#")) {
    return trimmed;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return parsed.toString();
    }
  } catch {
    return null;
  }

  return null;
}
