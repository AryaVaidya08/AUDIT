"use strict";

const SUPPORTED_TARGETS = Object.freeze({
  "darwin-arm64": "audit-darwin-arm64",
  "darwin-x64": "audit-darwin-x64",
  "linux-x64": "audit-linux-x64",
  "win32-x64": "audit-windows-x64.exe",
});

function resolveTarget(platform = process.platform, arch = process.arch) {
  const key = `${platform}-${arch}`;
  const asset = SUPPORTED_TARGETS[key];
  if (!asset) {
    const supported = Object.keys(SUPPORTED_TARGETS).join(", ");
    throw new Error(`Unsupported AUDIT target '${key}'. Supported targets: ${supported}.`);
  }
  return { key, platform, arch, asset };
}

function resolveAssetName(platform = process.platform, arch = process.arch) {
  return resolveTarget(platform, arch).asset;
}

module.exports = {
  SUPPORTED_TARGETS,
  resolveAssetName,
  resolveTarget,
};
