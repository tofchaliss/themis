// EDR-GUI-02 D7: apply the saved shade before the first paint, so a dark user never sees a
// light flash. Kept in step with src/lib/theme.ts (same key, same names, same fallback).
(function () {
  var names = ["enterprise", "midnight", "ops-night"];
  var t = "enterprise";
  try {
    var saved = localStorage.getItem("themis-theme");
    if (saved && names.indexOf(saved) >= 0) t = saved;
  } catch (e) {
    /* storage blocked: keep the default */
  }
  document.documentElement.setAttribute("data-theme", t);
})();
