import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import config from "./release.config.js";

// Resolve the plugin from semantic-release's own dependency graph: an independently
// installed generator could hide an incompatible writer on the actual release path.
const require = createRequire(import.meta.url);
const releaseRequire = createRequire(require.resolve("semantic-release"));
const generator = releaseRequire.resolve("@semantic-release/release-notes-generator");
const { generateNotes } = await import(pathToFileURL(generator));
const options = config.plugins.find(
  (plugin) => Array.isArray(plugin) && plugin[0] === "@semantic-release/release-notes-generator",
)[1];

test("configured release generator renders sections, breaking changes and GitHub links", async () => {
  const notes = await generateNotes(options, {
    cwd: fileURLToPath(new URL(".", import.meta.url)),
    branch: { name: "main" },
    options: {
      repositoryUrl: "https://github.com/cmeister2/tldhax.git",
      tagFormat: config.tagFormat,
    },
    lastRelease: { version: "1.0.0", gitTag: "1.0.0" },
    nextRelease: { version: "1.0.1", gitTag: "1.0.1" },
    commits: [
      { hash: "a".repeat(40), message: "feat: add a registry (#123)" },
      { hash: "b".repeat(40), message: "fix: preserve policy\n\nCloses #124" },
      {
        hash: "c".repeat(40),
        message: "feat!: update rules\n\nBREAKING CHANGE: use the new rule format",
      },
    ],
    logger: { log() {}, error() {} },
  });

  for (const expected of [
    "Features", "Bug Fixes", "BREAKING CHANGES", "use the new rule format",
    "add a registry", "preserve policy", "update rules",
    "https://github.com/cmeister2/tldhax/compare/1.0.0...1.0.1",
    "https://github.com/cmeister2/tldhax/issues/123",
    "https://github.com/cmeister2/tldhax/issues/124",
    `https://github.com/cmeister2/tldhax/commit/${"a".repeat(40)}`,
    `https://github.com/cmeister2/tldhax/commit/${"b".repeat(40)}`,
  ]) {
    assert.ok(notes.includes(expected), `Missing release-note output: ${expected}`);
  }
});
