"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { URL } = require("node:url");
const { resolveTarget } = require("./platform");

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 5;

function normalizeBaseUrl(rawValue) {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return trimmed;
  }
  return trimmed.replace(/\/+$/, "");
}

function parseRepositorySlug(repositoryField) {
  let raw = null;
  if (typeof repositoryField === "string") {
    raw = repositoryField;
  } else if (
    repositoryField &&
    typeof repositoryField === "object" &&
    typeof repositoryField.url === "string"
  ) {
    raw = repositoryField.url;
  }
  if (!raw) {
    return null;
  }

  let value = raw.trim().replace(/^git\+/, "").replace(/\.git$/, "");
  const sshMatch = value.match(/^git@github\.com:([^/]+\/[^/]+)$/i);
  if (sshMatch) {
    return sshMatch[1];
  }
  const shorthandMatch = value.match(/^github:([^/]+\/[^/]+)$/i);
  if (shorthandMatch) {
    return shorthandMatch[1];
  }

  try {
    const parsed = new URL(value);
    if (parsed.hostname.toLowerCase() !== "github.com") {
      return null;
    }
    const segments = parsed.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
    if (segments.length < 2) {
      return null;
    }
    return `${segments[0]}/${segments[1]}`;
  } catch {
    return null;
  }
}

function buildReleaseBaseUrl(pkg) {
  const override = process.env.AUDIT_BINARY_BASE_URL;
  if (override && override.trim()) {
    return normalizeBaseUrl(override);
  }

  const slug = parseRepositorySlug(pkg.repository);
  if (!slug || /^owner\/repo$/i.test(slug)) {
    throw new Error(
      "Unable to resolve GitHub repository from package.json. " +
        "Set AUDIT_BINARY_BASE_URL to your release base URL."
    );
  }

  return `https://github.com/${slug}/releases/download/v${pkg.version}`;
}

function requestBuffer(url, redirects = 0) {
  if (redirects > MAX_REDIRECTS) {
    return Promise.reject(new Error(`Too many redirects while downloading ${url}`));
  }

  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const client = parsedUrl.protocol === "http:" ? http : https;
    const request = client.get(
      parsedUrl,
      {
        headers: {
          "User-Agent": "audit-npm-wrapper/1.0",
        },
      },
      (response) => {
        const statusCode = response.statusCode || 0;
        if (REDIRECT_STATUS_CODES.has(statusCode)) {
          const location = response.headers.location;
          response.resume();
          if (!location) {
            reject(new Error(`Redirect response from ${url} had no Location header.`));
            return;
          }
          const redirectUrl = new URL(location, url).toString();
          resolve(requestBuffer(redirectUrl, redirects + 1));
          return;
        }

        if (statusCode !== 200) {
          let body = "";
          response.setEncoding("utf8");
          response.on("data", (chunk) => {
            if (body.length < 1000) {
              body += chunk;
            }
          });
          response.on("end", () => {
            const message = body.trim() ? ` ${body.trim()}` : "";
            reject(new Error(`Download failed (${statusCode}) for ${url}.${message}`));
          });
          return;
        }

        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks)));
      }
    );

    request.on("error", reject);
  });
}

function parseChecksums(contents) {
  const expected = new Map();
  const lines = contents.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const match = trimmed.match(/^([0-9a-fA-F]{64})\s{2}(.+)$/);
    if (!match) {
      continue;
    }
    const [, hash, assetName] = match;
    expected.set(assetName, hash.toLowerCase());
  }
  return expected;
}

async function main() {
  const packageRoot = path.resolve(__dirname, "..");
  const packageJsonPath = path.join(packageRoot, "package.json");
  const pkg = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
  const target = resolveTarget();
  const releaseBaseUrl = buildReleaseBaseUrl(pkg);
  const assetUrl = `${releaseBaseUrl}/${target.asset}`;
  const checksumUrl = `${releaseBaseUrl}/audit-checksums.txt`;

  console.log(`[audit] downloading ${target.asset} from ${releaseBaseUrl}`);

  const [binaryPayload, checksumPayload] = await Promise.all([
    requestBuffer(assetUrl),
    requestBuffer(checksumUrl),
  ]);

  const checksums = parseChecksums(checksumPayload.toString("utf8"));
  const expectedHash = checksums.get(target.asset);
  if (!expectedHash) {
    throw new Error(`audit-checksums.txt does not contain an entry for ${target.asset}`);
  }

  const actualHash = crypto.createHash("sha256").update(binaryPayload).digest("hex");
  if (actualHash !== expectedHash) {
    throw new Error(
      `Checksum mismatch for ${target.asset}: expected ${expectedHash}, got ${actualHash}.`
    );
  }

  const vendorDir = path.join(packageRoot, "vendor", target.key);
  const binaryName = target.platform === "win32" ? "audit.exe" : "audit";
  const binaryPath = path.join(vendorDir, binaryName);
  await fs.mkdir(vendorDir, { recursive: true });
  await fs.writeFile(binaryPath, binaryPayload);
  if (target.platform !== "win32") {
    await fs.chmod(binaryPath, 0o755);
  }

  console.log(`[audit] installed binary to ${binaryPath}`);
}

main().catch((error) => {
  console.error("[audit] postinstall failed.");
  console.error(error instanceof Error ? error.message : String(error));
  console.error(
    "Set AUDIT_BINARY_BASE_URL to a valid release base URL or verify that release assets exist."
  );
  process.exit(1);
});
