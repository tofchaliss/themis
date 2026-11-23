// EDR-GUI-02 D5: TypeScript types generated from the node OpenAPI specs (types only, no
// client runtime). `--check` fails when a committed file is out of date, so a node that
// renames a field breaks this build instead of the screen.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import openapiTS, { astToString } from "openapi-typescript";

const here = dirname(fileURLToPath(import.meta.url));
const apiDir = resolve(here, "../../../api");
const outDir = resolve(here, "../src/types/api");
const nodes = ["registry", "evidence", "knowledge", "governance", "communication", "intelligence"];
const check = process.argv.includes("--check");

mkdirSync(outDir, { recursive: true });
let stale = [];
for (const n of nodes) {
  const spec = new URL(`file://${resolve(apiDir, `${n}.openapi.yaml`)}`);
  const ast = await openapiTS(spec);
  const body = `// Generated from api/${n}.openapi.yaml by scripts/gen-api.mjs. Do not edit.\n\n${astToString(ast)}`;
  const out = resolve(outDir, `${n}.ts`);
  if (check) {
    if (!existsSync(out) || readFileSync(out, "utf8") !== body) stale.push(n);
  } else {
    writeFileSync(out, body);
  }
}
if (stale.length) {
  console.error(`API types out of date for: ${stale.join(", ")} — run \`npm run gen:api\` in web/dashboard`);
  process.exit(1);
}
console.log(check ? "api types: current" : `api types: wrote ${nodes.length} files`);
