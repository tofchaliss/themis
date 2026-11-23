import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules", "coverage", "src/types/api"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // EDR-GUI-02 D9: React escapes every value; raw HTML is the one way back to the
      // hand-escaped XSS class the old GUI had, so it is not allowed at all.
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Raw HTML is forbidden (EDR-GUI-02 D9)." },
        { selector: "MemberExpression[property.name='innerHTML']", message: "Raw HTML is forbidden (EDR-GUI-02 D9)." },
      ],
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    extends: [js.configs.recommended],
    languageOptions: { globals: { ...globals.node } },
  },
);
