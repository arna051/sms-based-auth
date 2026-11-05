import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = execFileSync("npm", ["pack", "--json", "--ignore-scripts"], {
  cwd: root,
  encoding: "utf8",
});
const [{ filename }] = JSON.parse(output);
const tarball = join(root, filename);
const temp = mkdtempSync(join(tmpdir(), "sms-based-auth-consumer-"));
try {
  writeFileSync(
    join(temp, "package.json"),
    JSON.stringify({ name: "consumer", private: true, type: "module" }),
  );
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      tarball,
      "express@5",
      "mongoose@9",
      "redis@6",
      "@nestjs/common@12",
      "@nestjs/core@12",
      "reflect-metadata@0.2",
      "rxjs@7",
    ],
    {
      cwd: temp,
      stdio: "pipe",
    },
  );
  const esm = [
    "sms-based-auth",
    "sms-based-auth/memory",
    "sms-based-auth/express",
    "sms-based-auth/nextjs",
    "sms-based-auth/edge",
    "sms-based-auth/transport",
    "sms-based-auth/redis",
    "sms-based-auth/mongoose",
    "sms-based-auth/nestjs",
  ];
  writeFileSync(
    join(temp, "esm.mjs"),
    `for (const name of ${JSON.stringify(esm)}) await import(name); console.log("esm ok");\n`,
  );
  writeFileSync(
    join(temp, "cjs.cjs"),
    `for (const name of ${JSON.stringify(esm)}) require(name); console.log("cjs ok");\n`,
  );
  execFileSync(process.execPath, ["esm.mjs"], { cwd: temp, stdio: "inherit" });
  execFileSync(process.execPath, ["cjs.cjs"], { cwd: temp, stdio: "inherit" });
  const types = readFileSync(
    join(temp, "node_modules/sms-based-auth/dist/index.d.ts"),
    "utf8",
  );
  if (!types.includes("createSmsBasedAuth"))
    throw new Error("declarations missing");
  execFileSync("npx", ["publint", root], { cwd: root, stdio: "inherit" });
  execFileSync(
    "npx",
    [
      "attw",
      "--pack",
      tarball,
      "--ignore-rules",
      "cjs-resolves-to-esm",
      "--profile",
      "node16",
    ],
    { cwd: root, stdio: "inherit" },
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
  rmSync(tarball, { force: true });
}
