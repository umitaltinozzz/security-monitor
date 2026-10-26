import { describe, expect, it } from "vitest";
import en from "./locales/en.json";
import tr from "./locales/tr.json";

const sources = import.meta.glob("./**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

type Tree = { [key: string]: string | Tree };

function lookup(tree: Tree, key: string): unknown {
  return key
    .split(".")
    .reduce<unknown>(
      (node, part) => (node && typeof node === "object" ? (node as Tree)[part] : undefined),
      tree,
    );
}

function leafKeys(tree: Tree, prefix = ""): string[] {
  return Object.entries(tree).flatMap(([key, value]) =>
    typeof value === "string" ? [`${prefix}${key}`] : leafKeys(value, `${prefix}${key}.`),
  );
}

// A key that resolves to nothing or to a section renders as raw text such as "findings.remediation".
describe("translations", () => {
  const usedKeys = new Set<string>();
  for (const [file, source] of Object.entries(sources)) {
    if (file.includes(".test.")) continue;
    for (const match of source.matchAll(/\bt\(\s*"([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+)"/g))
      if (match[1]) usedKeys.add(match[1]);
  }

  it("finds the keys used by the interface", () => {
    expect(usedKeys.size).toBeGreaterThan(100);
  });

  it.each([
    ["en", en as Tree],
    ["tr", tr as Tree],
  ])("resolves every static key to text in %s", (_language, tree) => {
    const missing = [...usedKeys].filter((key) => typeof lookup(tree, key) !== "string");
    expect(missing).toEqual([]);
  });

  it("keeps the English and Turkish key sets identical", () => {
    const english = new Set(leafKeys(en as Tree));
    const turkish = new Set(leafKeys(tr as Tree));
    expect([...english].filter((key) => !turkish.has(key))).toEqual([]);
    expect([...turkish].filter((key) => !english.has(key))).toEqual([]);
  });
});
