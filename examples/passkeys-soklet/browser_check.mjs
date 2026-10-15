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

// Test-only Chrome browser lanes. Node built-ins serve the exact DNS HTTPS edge.
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, mkdtemp, mkdir, open, writeFile, rm } from "node:fs/promises";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer } from "node:net";
import { arch, platform, release, tmpdir } from "node:os";
import { basename, delimiter, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const HOST = "passkeys.example.test";
const PHYSICAL_CEREMONY_TIMEOUT = 300_000;
const POST_ROUTES = new Set(["/access-login", "/register/start", "/register/finish",
  "/sign-in/start", "/sign-in/finish", "/reauth/start", "/reauth/finish",
  "/sensitive", "/credentials/list", "/credentials/remove", "/logout"]);
const execFileAsync = promisify(execFile);
const SENSITIVE_HEADERS = new Set([
  "host", "origin", "cookie", "content-type", "x-csrf-token", "x-ceremony-id",
  "x-credential-id", "x-demo-access-key"
]);

export function options(argv = process.argv.slice(2)) {
  const names = new Set(["--classpath-file", "--tls-dir", "--java", "--chrome"]);
  const strings = new Set(["--main-class", "--postgres-container", "--key-model",
    "--key-firmware", "--key-transport"]);
  const supplied = new Map();
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index];
    if (name === "--restart-app" || name === "--physical-key") {
      if (supplied.has(name)) throw new Error("Duplicate browser-check argument");
      supplied.set(name, true);
      continue;
    }
    if ((!names.has(name) && !strings.has(name) && name !== "--report-file")
        || !argv[index + 1]
        || argv[index + 1].startsWith("--") || supplied.has(name))
      throw new Error("Invalid browser-check arguments");
    const value = argv[++index];
    if ((name.startsWith("--key-") && (value.length > 120 || /[\u0000-\u001f\u007f]/u.test(value)))
        || (name === "--report-file" && !isAbsolute(value)))
      throw new Error("Key metadata must be bounded nonsecret text; report path must be absolute");
    supplied.set(name, strings.has(name) ? value : resolve(value));
  }
  if ([...names].some((name) => !supplied.has(name))
      || (supplied.has("--restart-app") && !supplied.has("--main-class"))
      || (supplied.has("--postgres-container") && (!supplied.has("--restart-app")
        || !/^revetsec-wa-[0-9a-f]{10}$/.test(supplied.get("--postgres-container")))))
    throw new Error("Missing browser-check arguments");
  if (!supplied.has("--physical-key") && ["--key-model", "--key-firmware", "--key-transport",
    "--report-file"].some((name) => supplied.has(name)))
    throw new Error("Physical-key metadata and reports require --physical-key");
  return supplied;
}

export function chromeArguments({ physical, profile, debugPort, pin }) {
  return [...(physical ? [] : ["--headless=new"]), "--no-first-run",
    "--no-default-browser-check", "--disable-background-networking", "--disable-extensions",
    "--no-proxy-server", `--user-data-dir=${profile}`, `--remote-debugging-port=${debugPort}`,
    `--host-resolver-rules=MAP ${HOST} 127.0.0.1`,
    `--ignore-certificate-errors-spki-list=${pin}`, "about:blank"];
}

export async function configureAuthenticator(cdp, physical) {
  if (physical) return null;
  await cdp.send("WebAuthn.enable");
  return cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb",
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    automaticPresenceSimulation: true
  } });
}

export async function preparePhysicalCeremony(cdp) {
  const prepared = await cdp.evaluate("(()=>{const preference=document.getElementById('security-key');"
    + "if(!preference||preference.type!=='checkbox')return false;preference.checked=true;"
    + "document.getElementById('status').textContent='';return true})()");
  if (!prepared) throw new Error("Physical-key browser preference is missing");
}

export function requireOutcome(outcomes, since, path, status) {
  const matching = outcomes.slice(since).filter((outcome) => outcome.path === path);
  if (matching.length !== 1 || matching[0].status !== status)
    throw new Error(`Expected one server response ${path} ${status}`);
}

async function jarHashes(classpath) {
  const jars = classpath.split(delimiter).filter((entry) => entry.endsWith(".jar"));
  if (jars.length > 32) throw new Error("Too many runtime JARs for bounded evidence");
  const hashes = [];
  for (const [index, path] of jars.entries()) {
    const hash = createHash("sha256");
    for await (const bytes of createReadStream(path)) hash.update(bytes);
    hashes.push({ classpathJarIndex: index, name: basename(path).slice(0, 120),
      sha256: hash.digest("hex") });
  }
  return hashes;
}

let interruptedSignal;

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
    if (interruptedSignal) throw new Error("Browser check interrupted by " + interruptedSignal);
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

  async evaluate(expression, userGesture = false) {
    const reply = await this.send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true, userGesture
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

async function waitPage(cdp, predicate, stage, timeout) {
  try {
    return await waitFor(async () => {
      const state = await pageState(cdp);
      return predicate(state) ? state : null;
    }, stage, timeout);
  } catch (failure) {
    throw new Error(stage + " failed with page state " + JSON.stringify(await pageState(cdp)),
      { cause: failure });
  }
}

async function click(cdp, selector) {
  const found = await cdp.evaluate("(()=>{const element=document.querySelector("
    + JSON.stringify(selector) + ");if(!element)return false;element.click();return true})()", true);
  if (!found) throw new Error("Browser control missing: " + selector);
}

async function stop(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
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
  const physical = args.has("--physical-key");
  const evidence = physical ? {
    schema: "revetsec-physical-passkey-check-v1", status: "incomplete",
    startedAt: new Date().toISOString(), finishedAt: null,
    environment: { node: process.version, os: platform(), osRelease: release(), arch: arch() },
    scope: { isolatedTestProfile: true, relyingParty: HOST, trust: "test leaf SPKI only",
      systemTrustChanged: false, virtualAuthenticatorUsed: false },
    ownerReportedKey: { model: args.get("--key-model") ?? null,
      firmware: args.get("--key-firmware") ?? null,
      transport: args.get("--key-transport") ?? null, verifiedByRunner: false },
    qualification: "Observed browser flow only; selected key and metadata require owner confirmation.",
    completedStages: [], routeOutcomes: [], runtimeJars: [], stage: "setup"
  } : null;
  // Exclusive creation avoids overwriting an existing report. No credential material is recorded.
  const report = args.has("--report-file") ? await open(args.get("--report-file"), "wx", 0o600) : null;
  let work;
  let app;
  let chrome;
  let edge;
  let cdp;
  let databaseStopped = false;
  const outcomes = [];
  const interrupt = (signal) => { interruptedSignal = signal; process.exitCode = signal === "SIGINT" ? 130 : 143; };
  const onInterrupt = () => interrupt("SIGINT");
  const onTerminate = () => interrupt("SIGTERM");
  process.on("SIGINT", onInterrupt);
  process.on("SIGTERM", onTerminate);
  try {
    const tls = args.get("--tls-dir");
    const cert = await readFile(join(tls, "leaf.crt"));
    const key = await readFile(join(tls, "leaf.key"));
    const pin = createHash("sha256").update(new X509Certificate(cert)
      .publicKey.export({ type: "spki", format: "der" })).digest("base64");
    const classpath = (await readFile(args.get("--classpath-file"), "utf8")).trim();
    if (evidence) evidence.runtimeJars = await jarHashes(classpath);
    work = await mkdtemp(join(tmpdir(), "revetsec-passkey-browser-"));
    const chromeProfile = join(work, "chrome-profile");
    const accessFile = join(work, "access-key");
    await mkdir(chromeProfile, { mode: 0o700 });
    await writeFile(accessFile, randomBytes(32).toString("base64url") + "\n", { mode: 0o600 });
    if (physical) process.stdout.write("Physical-key check: visible Chrome uses an isolated disposable test profile, "
      + "exact localhost DNS mapping and test-leaf SPKI trust only. PIN entry, authenticator selection "
      + "and touch stay in Chrome; never enter a PIN in this terminal.\n"
      + "Select your physical security key for every ceremony. This runner cannot attest the selected "
      + "key model or firmware. Each ceremony has a five-minute bounded wait.\n");

    function beginStage(stage, prompt) {
      if (evidence) evidence.stage = stage;
      if (physical && prompt) process.stdout.write(prompt + "\n");
      return outcomes.length;
    }
    function completeStage(stage, since, expected) {
      if (!physical) return;
      for (const [path, status] of expected) requireOutcome(outcomes, since, path, status);
      evidence.completedStages.push(stage);
      process.stdout.write("Observed " + stage + " server outcomes passed.\n");
    }
    async function ceremony(selector, stage, prompt, predicate, expected) {
      const since = beginStage(stage, prompt);
      if (physical) await preparePhysicalCeremony(cdp);
      await click(cdp, selector);
      if (physical) {
        const result = await waitFor(async () => {
          const state = await pageState(cdp);
          // Every completed ceremony writes a status or reloads. A terminal browser error
          // is incomplete evidence; it must never stand in for a server finish response.
          if (state.status && state.status !== "Signed in." && !predicate(state)) return { failed: true };
          return predicate(state) ? state : null;
        }, stage, PHYSICAL_CEREMONY_TIMEOUT);
        if (result.failed) throw new Error("Physical-key ceremony failed or was cancelled: " + stage);
      } else await waitPage(cdp, predicate, stage);
      completeStage(stage, since, expected);
    }
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
      let spawnFailed = false;
      child.once("error", () => { spawnFailed = true; });
      child.stderr.on("data", (bytes) => { appError = (appError + bytes.toString()).slice(-1000); });
      try {
        await waitFor(async () => {
          if (spawnFailed) throw new Error("Soklet JVM could not be started");
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
    chrome = spawn(args.get("--chrome"), chromeArguments({ physical, profile: chromeProfile, debugPort, pin }),
    { stdio: ["ignore", "ignore", "ignore"] });
    let chromeSpawnFailed = false;
    chrome.once("error", () => { chromeSpawnFailed = true; });
    const page = await waitFor(async () => {
      if (chromeSpawnFailed) throw new Error("Chrome could not be started");
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
    if (evidence) evidence.environment.browser = (await cdp.send("Browser.getVersion")).product;
    const virtual = await configureAuthenticator(cdp, physical);
    await cdp.send("Page.navigate", { url: origin + "/" });
    await waitPage(cdp, (state) => state.ready === "complete"
      && state.title === "Revetsec passkey demo" && state.secure, "HTTPS page");
    await cdp.evaluate("document.querySelector('#access').value="
      + JSON.stringify((await readFile(accessFile, "utf8")).trim()));
    await click(cdp, "#access-login");
    await waitPage(cdp, (state) => state.ready === "complete" && state.auth === "true",
      "access approval");
    await cdp.evaluate("document.querySelector('#management-access').value="
      + JSON.stringify((await readFile(accessFile, "utf8")).trim()));
    await ceremony("#register", "registration", "Register: choose your physical security key in Chrome, "
      + "enter its PIN there if requested, then touch the key.",
    (state) => state.status === "Passkey registered.", [["/register/start", 200], ["/register/finish", 200]]);
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
    if (!physical) {
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
    }
    await ceremony("#sign-in", "discoverable sign-in", "Sign in: select the passkey on the same "
      + "physical security key in Chrome, enter its PIN there if requested, then touch it.",
    (state) => state.ready === "complete" && state.auth === "true",
    [["/sign-in/start", 200], ["/sign-in/finish", 200]]);
    await ceremony("#reauth", "account-pinned reauthentication", "Reauthenticate: use the same "
      + "physical security key in Chrome and complete any PIN/touch prompt.",
    (state) => state.status === "Sensitive action approved for one use.",
    [["/reauth/start", 200], ["/reauth/finish", 200]]);
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
    let since = beginStage("one-use sensitive action");
    await click(cdp, "#sensitive");
    await waitPage(cdp, (state) => state.status === "Demo sensitive action completed.",
      "one-use sensitive action");
    completeStage("one-use sensitive action", since, [["/sensitive", 200]]);
    since = beginStage("step-up replay rejection");
    await click(cdp, "#sensitive");
    await waitPage(cdp, (state) => state.status === "Request denied.", "step-up replay rejection");
    completeStage("step-up replay rejection", since, [["/sensitive", 403]]);
    since = beginStage("credential list");
    await click(cdp, "#list");
    await waitPage(cdp, (state) => state.count === 1, "credential list");
    completeStage("credential list", since, [["/credentials/list", 200]]);
    await cdp.evaluate("document.querySelector('#management-access').value="
      + JSON.stringify((await readFile(accessFile, "utf8")).trim()));
    since = beginStage("server-side removal");
    await click(cdp, "#credentials li button");
    await waitPage(cdp, (state) => state.status === "Passkey removed." && state.count === 0,
      "server-side removal");
    completeStage("server-side removal", since, [["/credentials/remove", 200]]);
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
    await ceremony("#sign-in", "post-removal server rejection", "Removed passkey check: select the "
      + "same passkey still stored on your physical key and complete Chrome's PIN/touch prompt. "
      + "A browser cancellation does not prove server rejection.",
    (state) => state.status === "Authentication rejected.",
    [["/sign-in/start", 200], ["/sign-in/finish", 400]]);
    if (physical) {
      evidence.status = "passed";
      evidence.stage = "complete";
      process.stdout.write("Physical-key observed browser flow passed: register, sign in, account-pinned "
        + "reauthentication, one-use sensitive action, replay denial, list, remove and server rejection "
        + "of the removed credential.\n"
        + "Evidence comes from an isolated test profile; key identity/selection and metadata still require "
        + "owner confirmation. Server removal leaves the disposable test passkey on the key.\n");
    } else process.stdout.write("Chrome virtual WebAuthn browser flow passed: register, reject bogus "
        + "signature, sign in, reauthenticate, remove and reject removed credential"
        + (args.has("--restart-app") ? " across two Soklet restarts" : "")
        + (args.has("--postgres-container") ? " and a primary outage." : ".") + "\n");
  } finally {
    let recoveryFailure;
    let cleanupFailure;
    async function cleanup(task) {
      try { await task(); }
      catch (failure) { cleanupFailure ??= failure; }
    }
    if (databaseStopped) {
      try { await database("start", args.get("--postgres-container")); }
      catch (failure) { recoveryFailure = failure; }
    }
    await cleanup(() => cdp?.close());
    await cleanup(() => stop(chrome));
    await cleanup(() => stop(app));
    if (edge?.listening) await cleanup(() => new Promise((yes) => edge.close(yes)));
    if (work) await cleanup(() => rm(work, { recursive: true, force: true }));
    if (evidence) {
      evidence.finishedAt = new Date().toISOString();
      evidence.routeOutcomes = outcomes.slice(-128).map(({ path, status }) => ({
        path: POST_ROUTES.has(path) ? path : "other", status
      }));
      if (interruptedSignal) evidence.interruptedBy = interruptedSignal;
      if (recoveryFailure || cleanupFailure || interruptedSignal) evidence.status = "incomplete";
      if (cleanupFailure) evidence.cleanup = "incomplete";
    }
    if (report) {
      await cleanup(() => report.writeFile(JSON.stringify(evidence, null, 2) + "\n"));
      await cleanup(() => report.close());
    }
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
    if (recoveryFailure) throw recoveryFailure;
    if (cleanupFailure) throw cleanupFailure;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
