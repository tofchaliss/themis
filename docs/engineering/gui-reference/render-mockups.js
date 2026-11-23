// Re-renders the EDR-GUI-02 reference mockups from mockup.html (needs Playwright + Chromium).
// Run from anywhere: node docs/engineering/gui-reference/render-mockups.js
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 860 }, deviceScaleFactor: 1 });
  const f = 'file://' + __dirname + '/mockup.html';
  for (const [name, qs] of [
    ['posture-enterprise', 'theme=enterprise'], ['posture-midnight', 'theme=midnight'],
    ['posture-ops-night', 'theme=ops-night'], ['drawer-enterprise', 'theme=enterprise&drawer=1'],
    ['drawer-ops-night', 'theme=ops-night&drawer=1']]) {
    await p.goto(f + '?' + qs); await p.waitForTimeout(300);
    await p.screenshot({ path: __dirname + `/mockup-${name}.png` });
  }
  await b.close();
})();
