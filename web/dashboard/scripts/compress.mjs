// EDR-GUI-02 D8: write .br and .gz beside every compressible built file, so the dashboard
// sends the smallest one the browser accepts and spends no CPU compressing per request.
// Node's own zlib, fixed levels and no timestamps: the output is byte-stable (D3).
import { readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, gzipSync, constants } from "node:zlib";

const out = resolve(dirname(fileURLToPath(import.meta.url)), "../../../cmd/dashboard/static/next");
const compressible = /\.(js|css|html|svg|json)$/;

function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

let n = 0;
for (const f of walk(out)) {
  if (!compressible.test(f)) continue;
  const buf = readFileSync(f);
  if (buf.length < 1024) continue;
  writeFileSync(`${f}.br`, brotliCompressSync(buf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: buf.length } }));
  writeFileSync(`${f}.gz`, gzipSync(buf, { level: 9 }));
  n++;
}
console.log(`compress: ${n} files`);
