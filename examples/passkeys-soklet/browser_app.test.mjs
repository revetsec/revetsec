// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";

const source = await readFile(new URL("./src/main/resources/passkeys/app.js", import.meta.url), "utf8");
const copy = (value) => JSON.parse(JSON.stringify(value));

function browserPage({ checked, creation }) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      checked: id === "security-key" && checked, value: "demo-management-approval",
      textContent: "", listeners: new Map(),
      addEventListener(event, listener) { this.listeners.set(event, listener); }
    });
    return elements.get(id);
  }
  const originalOptions = creation ? {
    rp: { id: "passkeys.example.test", name: "Demo" },
    user: { id: "AQID", name: "demo", displayName: "Demo account" },
    challenge: "BAUG", pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", requireResidentKey: true,
      userVerification: "required" }, attestation: "none", extensions: { credProps: true }
  } : {
    rpId: "passkeys.example.test", challenge: "BAUG", userVerification: "required", timeout: 300_000
  };
  const browserCalls = [];
  const requests = [];
  const parsers = [];
  let reloads = 0;
  const credential = { toJSON: () => ({ type: "public-key", id: "AQID" }) };
  const PublicKeyCredential = {
    parseCreationOptionsFromJSON(options) { parsers.push("creation"); return copy(options); },
    parseRequestOptionsFromJSON(options) { parsers.push("request"); return copy(options); }
  };
  runInNewContext(source, {
    document: { body: { dataset: { csrf: "test-csrf", authenticated: "true" } },
      getElementById: element },
    window: { PublicKeyCredential, location: { reload() { reloads++; } } },
    PublicKeyCredential, DOMException,
    navigator: { credentials: {
      async create(options) { browserCalls.push({ method: "create", options: copy(options) }); return credential; },
      async get(options) { browserCalls.push({ method: "get", options: copy(options) }); return credential; }
    } },
    async fetch(path, options) {
      requests.push({ path, options: copy(options) });
      return { ok: true,
        async json() { return { ceremonyId: "test-ceremony", publicKey: copy(originalOptions) }; },
        async text() { return "Ceremony completed."; }
      };
    }
  });
  return {
    originalOptions, browserCalls, requests, parsers,
    async click(id) {
      await element(id).listeners.get("click")();
      assert.equal(element("status").textContent, "Ceremony completed.");
    },
    get reloads() { return reloads; }
  };
}

test("physical-key registration preserves discoverability and verification requirements", async () => {
  const page = browserPage({ checked: true, creation: true });
  await page.click("register");
  assert.deepEqual(page.parsers, ["creation"]);
  assert.deepEqual(page.browserCalls, [{ method: "create", options: { publicKey: {
    ...page.originalOptions, hints: ["security-key"], authenticatorSelection: {
      ...page.originalOptions.authenticatorSelection, authenticatorAttachment: "cross-platform"
    }
  } } }]);
  assert.deepEqual(page.requests.map(({ path }) => path), ["/register/start", "/register/finish"]);
  assert.equal(page.requests[1].options.headers["X-Ceremony-Id"], "test-ceremony");
});

test("ordinary registration leaves authenticator choice unrestricted", async () => {
  const page = browserPage({ checked: false, creation: true });
  await page.click("register");
  assert.deepEqual(page.browserCalls, [{ method: "create", options: { publicKey: page.originalOptions } }]);
  assert.equal("hints" in page.browserCalls[0].options.publicKey, false);
  assert.equal("authenticatorAttachment" in page.browserCalls[0].options.publicKey.authenticatorSelection, false);
});

test("physical-key sign-in and reauthentication use only the security-key hint", async () => {
  for (const [button, start, finish] of [["sign-in", "/sign-in/start", "/sign-in/finish"],
    ["reauth", "/reauth/start", "/reauth/finish"]]) {
    const page = browserPage({ checked: true, creation: false });
    await page.click(button);
    assert.deepEqual(page.parsers, ["request"]);
    assert.deepEqual(page.browserCalls, [{ method: "get", options: { publicKey: {
      ...page.originalOptions, hints: ["security-key"]
    } } }]);
    assert.equal("authenticatorSelection" in page.browserCalls[0].options.publicKey, false);
    assert.deepEqual(page.requests.map(({ path }) => path), [start, finish]);
    assert.equal(page.reloads, button === "sign-in" ? 1 : 0);
  }
});
