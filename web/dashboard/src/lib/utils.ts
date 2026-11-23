import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Initials for the user chip: "jane.doe" → "JD", "" → "·". */
export function initials(name: string): string {
  const out = name
    .split(/[\s._-]+/)
    .filter(Boolean)
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
  return out || "·";
}

/** "a list" from an API answer that is an array or an {items|entries} envelope. */
export function asArray<T>(j: unknown): T[] {
  if (Array.isArray(j)) return j as T[];
  if (j && typeof j === "object") {
    const o = j as { items?: unknown; entries?: unknown };
    if (Array.isArray(o.items)) return o.items as T[];
    if (Array.isArray(o.entries)) return o.entries as T[];
  }
  return [];
}
