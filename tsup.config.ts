import { defineConfig } from "tsup";
export default defineConfig({
  entry: {
    index: "src/index.ts",
    memory: "src/memory.ts",
    express: "src/express.ts",
    nextjs: "src/nextjs.ts",
    edge: "src/edge.ts",
    transport: "src/transport.ts",
    redis: "src/redis.ts",
    mongoose: "src/mongoose.ts",
    nestjs: "src/nestjs.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "node20",
  splitting: false,
});
