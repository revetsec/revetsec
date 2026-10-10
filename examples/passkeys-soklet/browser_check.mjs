// Copyright 2026 Revetware LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Test-only Chrome virtual-authenticator lane. Node built-ins serve the exact DNS HTTPS edge.
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { readFile, mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const HOST = "passkeys.example.test";
const execFileAsync = promisify(execFile);
const SENSITIVE_HEADERS = new Set([
  "host", "origin", "cookie", "content-type", "x-csrf-token", "x-ceremony-id",
  "x-credential-id", "x-demo-access-key"
]);

function options() {
  const names = new Set(["--classpath-file", "--tls-dir", "--java", "--chrome"]);
  const supplied = new Map();
  for (let index = 2; index < process.argv.length; index++) {
    const name = process.argv[index];
    if (name === "--restart-app") {
      if (supplied.has(name)) throw new Error("Duplicate browser-check argument");
      supplied.set(name, true);
      continue;
    }
    if ((!names.has(name) && name !== "--main-class" && name !== "--postgres-container")
        || !process.argv[index + 1]
        || process.argv[index + 1].startsWith("--") || supplied.has(name))
      throw new Error("Invalid browser-check arguments");
    supplied.set(name, name === "--main-class" || name === "--postgres-container" ? process.argv[++index]
      : resolve(process.argv[++index]));
  }
  if ([...names].some((name) => !supplied.has(name))
      || (supplied.has("--restart-app") && !supplied.has("--main-class"))
      || (supplied.has("--postgres-container") && (!supplied.has("--restart-app")
        || !/^revetsec-wa-[0-9a-f]{10}$/.test(supplied.get("--postgres-container")))))
    throw new Error("Missing browser-check arguments");
  return supplied;
}

async function freePort() {
  const server = createNetServer();
  await new Promise((yes, no) => server.once("error", no).listen(0, "127.0.0.1", yes));
  const port = server.address().port;
  await new Promise((yes) => server.close(yes));
  return port;
}

async function waitFor(task, description, timeout = 15_000) {
  const limit = Date.now() + timeout;
  let last;
  while (Date.now() < limit) {
    try {
      const result = await task();
      if (result) return result;
      last = result;
    } catch (error) { last = error; }
    await new Promise((yes) => setTimeout(yes, 80));
  }
  throw new Error(description + " timed out" + (last instanceof Error ? ": " + last.message : ""));
}

function secureEdge(cert, key, appPort, outcomes) {
  const server = createHttpsServer({ cert, key }, (incoming, outgoing) => {
    const expectedHost = `${HOST}:${server.address().port}`;
    const seen = new Set();
    for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
      const name = incoming.rawHeaders[index].toLowerCase();
      if (SENSITIVE_HEADERS.has(name) && seen.has(name)) {
        outgoing.writeHead(400).end();
        return;
      }
      seen.add(name);
    }
    if (incoming.headers.host !== expectedHost) {
      outgoing.writeHead(403).end();
      return;
    }
    const upstream = httpRequest({ host: "127.0.0.1", port: appPort,
      method: incoming.method, path: incoming.url,
      headers: { ...incoming.headers, host: expectedHost } }, (response) => {
      if (incoming.method === "POST") outcomes.push({ path: incoming.url,
        status: response.statusCode });
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on("error", () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
    incoming.pipe(upstream);
  });
  return server;
}

class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result ?? {});
    });
    socket.addEventListener("close", () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("Chrome DevTools connection closed"));
      }
      this.pending.clear();
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(method + " timed out"));
      }, 15_000);
      this.pending.set(id, { resolve: resolvePromise, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const reply = await this.send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true
    });
    if (reply.exceptionDetails) throw new Error("Chrome page expression failed");
    return reply.result?.value;
  }

  close() { this.socket.close(); }
}

async function pageState(cdp) {
  return cdp.evaluate("({ready:document.readyState,auth:document.body?.dataset.authenticated," +
    "status:document.getElementById('status')?.textContent," +
    "count:document.querySelectorAll('#credentials li').length," +
    "title:document.title,secure:isSecureContext})");
}

async function waitPage(cdp, predicate, stage) {
  try {
    return await waitFor(async () => {
      const state = await pageState(cdp);
      return predicate(state) ? state : null;
    }, stage);
  } catch (failure) {
    throw new Error(stage + " failed with page state " + JSON.stringify(await pageState(cdp)),
      { cause: failure });
  }
}

async function click(cdp, selector) {
  const found = await cdp.evaluate("(()=>{const element=document.querySelector("
    + JSON.stringify(selector) + ");if(!element)return false;element.click();return true})()");
  if (!found) throw new Error("Browser control missing: " + selector);
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((yes) => child.once("exit", yes)),
    new Promise((yes) => setTimeout(yes, 2_000))
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await new Promise((yes) => child.once("exit", yes));
  }
}

async function database(command, container) {
  await execFileAsync("docker", [command, container], { timeout: 30_000, maxBuffer: 4_096 });
}

async function main() {
  const args = options();
  const tls = args.get("--tls-dir");
  const cert = await readFile(join(tls, "leaf.crt"));
  const key = await readFile(join(tls, "leaf.key"));
  const pin = createHash("sha256").update(new X509Certificate(cert)
    .publicKey.export({ type: "spki", format: "der" })).digest("base64");
  const classpath = (await readFile(args.get("--classpath-file"), "utf8")).trim();
  const work = await mkdtemp(join(tmpdir(), "revetsec-passkey-browser-"));
  const chromeProfile = join(work, "chrome-profile");
  const accessFile = join(work, "access-key");
  await mkdir(chromeProfile, { mode: 0o700 });
  await writeFile(accessFile, randomBytes(32).toString("base64url") + "\n", { mode: 0o600 });
  let app;
  let chrome;
  let edge;
  let cdp;
  let databaseStopped = false;
  const outcomes = [];
  try {
    const appPort = await freePort();
    edge = secureEdge(cert, key, appPort, outcomes);
    await new Promise((yes, no) => edge.once("error", no).listen(0, "127.0.0.1", yes));
    const edgePort = edge.address().port;
    const authority = `${HOST}:${edgePort}`;
    const origin = `https://${authority}`;
    async function startApp() {
      const child = spawn(args.get("--java"), ["-cp", classpath,
        args.get("--main-class") ?? "example.passkeys.PasskeyPlayground"], {
        env: { ...process.env, REVETSEC_PASSKEY_RP_ID: HOST,
          REVETSEC_PASSKEY_ORIGIN: origin, REVETSEC_PASSKEY_HTTP_PORT: String(appPort),
          REVETSEC_PASSKEY_ACCESS_KEY_FILE: accessFile },
        stdio: ["ignore", "ignore", "pipe"]
      });
      let appError = "";
      child.stderr.on("data", (bytes) => { appError = (appError + bytes.toString()).slice(-1000); });
      try {
        await waitFor(async () => {
          if (child.exitCode !== null) throw new Error("Soklet app exited: " + appError);
          return new Promise((yes) => {
            const probe = httpRequest({ host: "127.0.0.1", port: appPort, path: "/",
              headers: { Host: authority } }, (response) => {
              response.resume();
              yes(response.statusCode === 200);
            });
            probe.on("error", () => yes(false));
            probe.end();
          });
        }, "Soklet startup");
      } catch (failure) {
        await stop(child);
        throw new Error("Soklet startup failed: " + appError.slice(-1000), { cause: failure });
      }
      return child;
    }
    app = await startApp();

    const debugPort = await freePort();
    chrome = spawn(args.get("--chrome"), ["--headless=new", "--no-first-run",
      "--no-default-browser-check", "--disable-background-networking", "--disable-extensions",
      "--no-proxy-server", `--user-data-dir=${chromeProfile}`,
      `--remote-debugging-port=${debugPort}`,
      `--host-resolver-rules=MAP ${HOST} 127.0.0.1`,
      `--ignore-certificate-errors-spki-list=${pin}`, "about:blank"],
    { stdio: ["ignore", "ignore", "ignore"] });
    const page = await waitFor(async () => {
      if (chrome.exitCode !== null) throw new Error("Chrome exited before DevTools became ready");
      const response = await fetch(`http://127.0.0.1:${debugPort}/json/list`);
      const targets = await response.json();
      return targets.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
    }, "Chrome DevTools startup");
    const socket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((yes, no) => {
      socket.addEventListener("open", yes, { once: true });
      socket.addEventListener("error", no, { once: true });
    });
    cdp = new Cdp(socket);
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("WebAuthn.enable");
    const virtual = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb",
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true
    } });
    await cdp.send("Page.navigate", { url: origin + "/" });
    await waitPage(cdp, (state) => state.ready === "complete"
      && state.title === "Revetsec passkey demo" && state.secure, "HTTPS page");
    await cdp.evaluate("document.querySelector('#access').value="
      + JSON.stringify((await readFile(accessFile, "utf8")).trim()));
    await click(cdp, "#access-login");
    await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "true",
      "access approval");
    await click(cdp, "#register");
    await waitPage(cdp, (state) => state.status === "Passkey registered.", "browser registration");
    if (args.has("--restart-app")) {
      await stop(app);
      app = await startApp();
      await cdp.send("Page.navigate", { url: origin + "/" });
      await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "false",
        "anonymous browser after application restart");
    } else {
      await click(cdp, "#logout");
      await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "false",
        "logout");
    }
    await cdp.send("WebAuthn.setResponseOverrideBits", {
      authenticatorId: virtual.authenticatorId, isBogusSignature: true
    });
    await click(cdp, "#sign-in");
    await waitPage(cdp, (state) => state.auth === "false"
      && state.status === "Authentication rejected.", "bogus browser assertion denial");
    if (outcomes.at(-1)?.path !== "/sign-in/finish" || outcomes.at(-1)?.status !== 400)
      throw new Error("Bogus browser signature did not reach Revetsec's denial path");
    await cdp.send("WebAuthn.setResponseOverrideBits", {
      authenticatorId: virtual.authenticatorId
    });
    await click(cdp, "#sign-in");
    await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "true",
      "discoverable sign-in");
    await click(cdp, "#reauth");
    await waitPage(cdp, (state) => state.status === "Sensitive action approved for one use.",
      "account-pinned reauthentication");
    if (args.has("--postgres-container")) {
      const container = args.get("--postgres-container");
      await database("stop", container);
      databaseStopped = true;
      try {
        const unavailablePage = await cdp.evaluate("fetch('/').then(response=>response.status)");
        if (unavailablePage !== 503) throw new Error("Closed database served an account page");
        await click(cdp, "#sensitive");
        await waitPage(cdp, (state) => state.status === "Local demo unavailable.",
          "sensitive action during primary outage");
        if (outcomes.at(-1)?.path !== "/sensitive" || outcomes.at(-1)?.status !== 503)
          throw new Error("Primary outage did not close the sensitive action");
      } finally {
        await database("start", container);
        databaseStopped = false;
      }
      await waitFor(async () => await cdp.evaluate("fetch('/').then(response=>response.status)")
        === 200, "account page after primary restart");
    }
    await click(cdp, "#sensitive");
    await waitPage(cdp, (state) => state.status === "Demo sensitive action completed.",
      "one-use sensitive action");
    await click(cdp, "#sensitive");
    await waitPage(cdp, (state) => state.status === "Request denied.", "step-up replay rejection");
    await click(cdp, "#list");
    await waitPage(cdp, (state) => state.count === 1, "credential list");
    await click(cdp, "#credentials li button");
    await waitPage(cdp, (state) => state.status === "Passkey removed." && state.count === 0,
      "server-side removal");
    if (args.has("--restart-app")) {
      await stop(app);
      app = await startApp();
      await cdp.send("Page.navigate", { url: origin + "/" });
      await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "false",
        "anonymous browser after removal restart");
    } else {
      await click(cdp, "#logout");
      await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "false",
        "final logout");
    }
    await click(cdp, "#sign-in");
    await waitPage(cdp, (state) => state.status === "Authentication rejected.",
      "post-removal browser rejection");
    process.stdout.write("Chrome virtual WebAuthn browser flow passed: register, reject bogus "
      + "signature, sign in, reauthenticate, remove and reject removed credential"
      + (args.has("--restart-app") ? " across two Soklet restarts" : "")
      + (args.has("--postgres-container") ? " and a primary outage." : ".") + "\n");
  } finally {
    let recoveryFailure;
    if (databaseStopped) {
      try { await database("start", args.get("--postgres-container")); }
      catch (failure) { recoveryFailure = failure; }
    }
    cdp?.close();
    await stop(chrome);
    await stop(app);
    if (edge?.listening) await new Promise((yes) => edge.close(yes));
    await rm(work, { recursive: true, force: true });
    if (recoveryFailure) throw recoveryFailure;
  }
}

await main();
