import { defineConfig } from 'tsup';
export default defineConfig({ entry: { index: 'src/index.ts', memory: 'src/memory.ts', express: 'src/express.ts' }, format: ['esm', 'cjs'], dts: true, clean: true, sourcemap: true, target: 'node20', splitting: false });
