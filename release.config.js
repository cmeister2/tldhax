module.exports = {
  branches: ["main"],
  tagFormat: "${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { breaking: true, release: "patch" },
          { type: "feat", release: "patch" },
          { type: "fix", release: "patch" }
        ]
      }
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits"
      }
    ],
    "@semantic-release/github",
    [
      "@semantic-release/exec",
      {
        verifyReleaseCmd: "./publish.sh ${nextRelease.version}"
      }
    ]
  ]
};
