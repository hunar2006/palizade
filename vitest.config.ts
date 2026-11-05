import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["packages/**/*.test.ts"],
    pool: "threads",
    fileParallelism: true,
    // Tests that open SQLite stores and hook engines many times run several times slower on
    // Windows runners; 5 s timed out there while passing everywhere else.
    testTimeout: 30_000
  }
});
