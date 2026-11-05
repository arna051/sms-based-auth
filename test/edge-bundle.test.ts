import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

describe("Edge bundle", () => {
  it("bundles for browsers without Node built-ins or signing secrets", async () => {
    const directory = await mkdtemp(join(tmpdir(), "sms-auth-edge-"));
    const outfile = join(directory, "edge.js");
    try {
      const result = await build({
        entryPoints: ["src/edge.ts"],
        outfile,
        bundle: true,
        platform: "browser",
        format: "esm",
        target: "es2022",
        metafile: true,
        write: true,
      });
      const inputs = Object.keys(result.metafile.inputs);
      expect(
        inputs.some(
          (name) =>
            name.includes("mongoose") ||
            name.includes("redis") ||
            name.startsWith("node:"),
        ),
      ).toBe(false);
      const code = await readFile(outfile, "utf8");
      expect(code).not.toContain("node:crypto");
      expect(code).not.toContain("privateKey");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
