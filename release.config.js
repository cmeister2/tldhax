module.exports = {
  branches: ["main"],
  tagFormat: "${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { type: "breaking", release: "patch" },
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
        publishCmd: "./publish.sh ${nextRelease.version}"
      }
    ]
  ]
};