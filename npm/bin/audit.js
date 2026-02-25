#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { resolveTarget } = require("../scripts/platform");

const HELP_FLAGS = new Set(["-h", "--help"]);

function resolveCacheRoot() {
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Caches", "audit");
  }
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    return path.join(localAppData, "audit");
  }
  const xdgCacheHome = process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  return path.join(xdgCacheHome, "audit");
}

function isHelpInvocation(args) {
  if (args.length === 0) {
    return false;
  }
  if (args.length === 1 && (HELP_FLAGS.has(args[0]) || args[0] === "help")) {
    return true;
  }
  if (args[0] === "scan" && args.some((arg) => HELP_FLAGS.has(arg))) {
    return true;
  }
  return false;
}

function requiresApiKey(args) {
  if (isHelpInvocation(args)) {
    return false;
  }
  if (args.length === 1 && ["--version", "--install-completion", "--show-completion"].includes(args[0])) {
    return false;
  }
  if (args[0] === "help") {
    return false;
  }
  if (args[0] === "scan" && args.some((arg) => HELP_FLAGS.has(arg))) {
    return false;
  }
  return true;
}

function resolveBinaryPath() {
  const target = resolveTarget();
  const binaryName = target.platform === "win32" ? "audit.exe" : "audit";
  return {
    target,
    path: path.join(__dirname, "..", "vendor", target.key, binaryName),
  };
}

function initializeCacheDefaults(env) {
  const preferredRoot = resolveCacheRoot();
  const fallbackRoot = path.join(os.tmpdir(), "audit");
  let cacheRoot = preferredRoot;
  let chromaPersistDir = path.join(cacheRoot, "chroma");

  try {
    fs.mkdirSync(cacheRoot, { recursive: true });
    fs.mkdirSync(chromaPersistDir, { recursive: true });
  } catch (error) {
    cacheRoot = fallbackRoot;
    chromaPersistDir = path.join(cacheRoot, "chroma");
    try {
      fs.mkdirSync(cacheRoot, { recursive: true });
      fs.mkdirSync(chromaPersistDir, { recursive: true });
    } catch (fallbackError) {
      const preferredError = error instanceof Error ? error.message : String(error);
      const fallbackErrorText = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
      throw new Error(
        `Unable to initialize cache directories (${preferredRoot} or ${fallbackRoot}): ` +
          `${preferredError}; ${fallbackErrorText}`
      );
    }
  }

  if (!env.SCAN_CACHE_PATH) {
    env.SCAN_CACHE_PATH = path.join(cacheRoot, "scan_cache.sqlite3");
  }
  if (!env.SCAN_CHECKPOINT_PATH) {
    env.SCAN_CHECKPOINT_PATH = path.join(cacheRoot, "scan_resume.json");
  }
  if (!env.CHROMA_PERSIST_DIR) {
    env.CHROMA_PERSIST_DIR = chromaPersistDir;
  }
}

function main() {
  const args = process.argv.slice(2);
  const binary = resolveBinaryPath();
  const env = { ...process.env };

  if (!fs.existsSync(binary.path)) {
    console.error(
      `AUDIT binary is missing for ${binary.target.key}. Reinstall the package so postinstall can download it.`
    );
    process.exit(1);
  }

  if (requiresApiKey(args) && !env.OPENAI_API_KEY) {
    console.error("OPENAI_API_KEY is required to run scans.");
    console.error("Set it first, for example: export OPENAI_API_KEY=your-key");
    console.error("Use `audit --help` for usage details.");
    process.exit(2);
  }

  try {
    initializeCacheDefaults(env);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }

  const child = spawn(binary.path, args, { stdio: "inherit", env });
  child.on("error", (error) => {
    console.error(`Failed to launch AUDIT binary: ${error.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code == null ? 1 : code);
  });
}

main();
