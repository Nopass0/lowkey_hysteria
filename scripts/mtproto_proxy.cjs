"use strict";

const fs = require("fs");
const net = require("net");
const path = require("path");
const dotenv = require("dotenv");

function patchMtprotoProxyModule() {
  const modulePath = require.resolve("mtprotoproxy");
  const source = fs.readFileSync(modulePath, "utf8");

  let patched = source.replace(
    /AD_TAG=Buffer\.from\(AD_TAG,'hex'\)/g,
    "AD_TAG=Buffer.from(AD_TAG||'','hex')",
  );

  patched = patched.replace(
    /assertit\(dcId>=-5\);\s*assertit\(dcId<=5\);\s*assertit\(dcId!==0\);/g,
    "assertit(dc[dcId]&&dc[dcId].length>0,'Unknown dcId');",
  );

  if (patched !== source) {
    fs.writeFileSync(modulePath, patched, "utf8");
  }
}

patchMtprotoProxyModule();

const { MTProtoProxy } = require("mtprotoproxy");

dotenv.config({ path: path.resolve(__dirname, "..", ".env") });

function parseBoolean(value, fallback = false) {
  if (value == null || value === "") {
    return fallback;
  }

  switch (String(value).trim().toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      return fallback;
  }
}

function normalizePort(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) {
    return parsed;
  }
  return fallback;
}

function requireSecret(value) {
  const secret = String(value ?? "").trim().toLowerCase();
  if (!/^(dd|ee)[0-9a-f]{32}$/.test(secret)) {
    throw new Error(
      "MTPROTO_SECRET must start with dd or ee and contain 32 hex chars after the prefix",
    );
  }
  return secret;
}

function normalizeAdTag(value) {
  const adTag = String(value ?? "").trim().toLowerCase();
  if (!adTag) {
    return "";
  }
  if (!/^[0-9a-f]{32}$/.test(adTag)) {
    throw new Error("MTPROTO_AD_TAG must be 32 hex characters");
  }
  return adTag;
}

const enabled = parseBoolean(process.env.MTPROTO_ENABLED, false);
if (!enabled) {
  console.log("[MTProto] Disabled via MTPROTO_ENABLED=false");
  process.exit(0);
}

const listenHost = "0.0.0.0";
const listenPort = normalizePort(process.env.MTPROTO_PORT, 8443);
const secret = requireSecret(process.env.MTPROTO_SECRET);
const sponsorEnabled = parseBoolean(process.env.MTPROTO_ADD_CHANNEL, false);
const adTag = normalizeAdTag(process.env.MTPROTO_AD_TAG);
const sponsorChannel = String(process.env.MTPROTO_CHANNEL_USERNAME ?? "").trim();
const sponsorBot = String(process.env.MTPROTO_BOT_USERNAME ?? "").trim();
const sponsorLabel = sponsorBot || sponsorChannel || "";
let readyReached = false;
const readyWatchdog = setTimeout(() => {
  if (!readyReached) {
    console.warn(
      "[MTProto] Still waiting for Telegram proxy bootstrap data. Check outbound access to core.telegram.org.",
    );
  }
}, 15_000);

console.log(
  `[MTProto] Booting on ${listenHost}:${listenPort}${sponsorLabel ? `; sponsor=${sponsorLabel}` : ""}`,
);

if (sponsorEnabled && !adTag) {
  console.warn(
    "[MTProto] Sponsor mode is enabled but MTPROTO_AD_TAG is empty. Telegram will not show the sponsor channel/bot.",
  );
}

let proxyServer = null;
let activeConnections = 0;

const mtproto = new MTProtoProxy({
  secrets: [secret],
  async enter(options) {
    activeConnections += 1;
    const remoteIp = options?.address ?? "unknown";
    console.log(
      `[MTProto] Client connected ${remoteIp}; active=${activeConnections}`,
    );

    if (sponsorEnabled && adTag) {
      return adTag;
    }

    // mtprotoproxy expects a hex string here and later calls Buffer.from(...)
    // unconditionally, so empty string is the safe "no sponsor" value.
    return "";
  },
  leave(options) {
    activeConnections = Math.max(0, activeConnections - 1);
    const errorText =
      options?.error instanceof Error
        ? options.error.message
        : options?.error
          ? String(options.error)
          : "";
    if (errorText) {
      console.warn(
        `[MTProto] Client disconnected with error; active=${activeConnections}; error=${errorText}`,
      );
      return;
    }

    console.log(`[MTProto] Client disconnected; active=${activeConnections}`);
  },
  ready() {
    readyReached = true;
    clearTimeout(readyWatchdog);
    proxyServer = net.createServer(mtproto.proxy);
    proxyServer.on("error", (error) => {
      console.error("[MTProto] Proxy server error:", error);
      process.exitCode = 1;
    });
    proxyServer.listen(listenPort, listenHost, () => {
      console.log(
        `[MTProto] Listening on ${listenHost}:${listenPort}${sponsorLabel ? `; sponsor=${sponsorLabel}` : ""}`,
      );
    });
  },
});

function shutdown(signal) {
  console.log(`[MTProto] ${signal} received, shutting down`);
  if (proxyServer) {
    proxyServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3_000).unref();
    return;
  }
  process.exit(0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
