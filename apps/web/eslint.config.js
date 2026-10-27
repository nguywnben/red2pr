import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "coverage/**", "node_modules/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  jsxA11y.flatConfigs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // babel-plugin-react-compiler is not enabled; suppress informational compiler hint on TanStack Virtual.
      "react-hooks/incompatible-library": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "SEC-040: dangerouslySetInnerHTML is prohibited in Red2PR web UI; render untrusted text via sanitized plain-text nodes.",
        },
      ],
    },
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: [
      "src/shared/ui/**/*.{ts,tsx}",
      "src/shared/theme/**/*.{ts,tsx}",
      "src/shared/i18n/**/*.{ts,tsx}",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@astryxdesign/*"],
              message:
                "FE-05: Direct @astryxdesign/* imports are isolated behind src/shared/ui/, src/shared/theme/, and src/shared/i18n/ wrappers.",
            },
          ],
        },
      ],
    },
  },
);
