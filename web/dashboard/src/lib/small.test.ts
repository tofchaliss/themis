import { describe, expect, it } from "vitest";
import { applyTheme, isTheme, loadTheme } from "./theme";
import { classicHref, parseHash } from "./router";
import { asArray, initials } from "./utils";
import { bandSlices } from "@/components/bands";

describe("theme", () => {
  it("defaults to Enterprise and ignores unknown names", () => {
    expect(loadTheme()).toBe("enterprise");
    localStorage.setItem("themis-theme", "retired");
    expect(loadTheme()).toBe("enterprise");
  });

  it("applies and remembers a shade", () => {
    applyTheme("ops-night");
    expect(document.documentElement.dataset.theme).toBe("ops-night");
    expect(loadTheme()).toBe("ops-night");
    expect(isTheme("midnight")).toBe(true);
    expect(isTheme("dark")).toBe(false);
  });

  it("still applies when storage is blocked", () => {
    const proto = Object.getPrototypeOf(localStorage) as Storage;
    const set = proto.setItem;
    const get = proto.getItem;
    proto.setItem = () => {
      throw new Error("blocked");
    };
    proto.getItem = () => {
      throw new Error("blocked");
    };
    try {
      applyTheme("midnight");
      expect(document.documentElement.dataset.theme).toBe("midnight");
      expect(loadTheme()).toBe("enterprise");
    } finally {
      proto.setItem = set;
      proto.getItem = get;
    }
  });
});

describe("router", () => {
  it("keeps today's hash shapes", () => {
    expect(parseHash("")).toEqual({ view: "overview" });
    expect(parseHash("#/")).toEqual({ view: "overview" });
    expect(parseHash("#/estate")).toEqual({ view: "estate" });
    expect(parseHash("#/release/r1?v=1.0")).toEqual({ view: "classic", hash: "#/release/r1?v=1.0" });
  });

  it("builds classic GUI links", () => {
    expect(classicHref("#/sbom")).toBe("/old/#/sbom");
    expect(classicHref("/feeds")).toBe("/old/#/feeds");
  });
});

describe("utils", () => {
  it("makes initials", () => {
    expect(initials("jane.doe")).toBe("JD");
    expect(initials("operator")).toBe("O");
    expect(initials("")).toBe("·");
  });

  it("reads lists and envelopes", () => {
    expect(asArray([1])).toEqual([1]);
    expect(asArray({ items: [2] })).toEqual([2]);
    expect(asArray({ entries: [3] })).toEqual([3]);
    expect(asArray(null)).toEqual([]);
    expect(asArray({})).toEqual([]);
  });
});

describe("bands", () => {
  it("counts in fixed order and keeps unbanded", () => {
    const s = bandSlices(["high", "critical", "high", undefined, "weird"]);
    expect(s.map((x) => [x.id, x.n])).toEqual([
      ["critical", 1],
      ["high", 2],
      ["unbanded", 2],
    ]);
  });
});
