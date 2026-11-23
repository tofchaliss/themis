// EDR-GUI-02 D8: the first load (index.html's own script and the modules it preloads) must
// stay under the budget, gzipped. CI fails past it, so the GUI cannot grow heavy unnoticed.
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const BUDGET_KB = 150;
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../../../cmd/dashboard/static/next");
const html = readFileSync(resolve(out, "index.html"), "utf8");
const refs = [...html.matchAll(/(?:src|href)="\/next\/(assets\/[^"]+\.(?:js|css))"/g)].map((m) => m[1]);
let total = 0;
for (const r of new Set(refs)) {
  const gz = gzipSync(readFileSync(resolve(out, r)), { level: 9 }).length;
  total += gz;
  console.log(`  ${r}  ${(gz / 1024).toFixed(1)} KB gz`);
}
const kb = total / 1024;
console.log(`first load: ${kb.toFixed(1)} KB gzipped (budget ${BUDGET_KB} KB)`);
if (kb > BUDGET_KB) {
  console.error(`size budget exceeded: ${kb.toFixed(1)} KB > ${BUDGET_KB} KB (EDR-GUI-02 D8)`);
  process.exit(1);
}
