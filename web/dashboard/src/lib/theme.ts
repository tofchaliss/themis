// EDR-GUI-02 D7: three shades. The key is the old GUI's, so a choice made in either GUI
// carries over; an unknown or retired name falls back to the default.
export const THEMES = [
  { id: "enterprise", label: "Enterprise" },
  { id: "midnight", label: "Midnight" },
  { id: "ops-night", label: "Ops night" },
] as const;

export type ThemeId = (typeof THEMES)[number]["id"];
export const DEFAULT_THEME: ThemeId = "enterprise";
const KEY = "themis-theme";

export function isTheme(v: unknown): v is ThemeId {
  return THEMES.some((t) => t.id === v);
}

export function loadTheme(): ThemeId {
  try {
    const saved = localStorage.getItem(KEY);
    return isTheme(saved) ? saved : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

export function applyTheme(t: ThemeId) {
  document.documentElement.setAttribute("data-theme", t);
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage blocked: the shade still applies for this page */
  }
}
