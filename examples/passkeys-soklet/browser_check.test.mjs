// Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
import assert from "node:assert/strict";
import test from "node:test";
import { chromeArguments, configureAuthenticator, options, requireOutcome } from "./browser_check.mjs";

const required = ["--classpath-file", "/tmp/classpath", "--tls-dir", "/tmp/tls",
  "--java", "/tmp/java", "--chrome", "/tmp/chrome"];

test("physical mode never enables or supplies a virtual authenticator", async () => {
  const commands = [];
  const cdp = { send: async (method) => { commands.push(method); return {}; } };
  assert.equal(await configureAuthenticator(cdp, true), null);
  assert.deepEqual(commands, []);
  await configureAuthenticator(cdp, false);
  assert.deepEqual(commands, ["WebAuthn.enable", "WebAuthn.addVirtualAuthenticator"]);
});

test("physical Chrome is visible and scoped to a disposable profile and leaf SPKI", () => {
  const input = { profile: "/tmp/private-profile", debugPort: 12345, pin: "test-pin" };
  const physical = chromeArguments({ ...input, physical: true });
  assert.equal(physical.some((arg) => arg.startsWith("--headless")), false);
  assert.ok(physical.includes("--user-data-dir=/tmp/private-profile"));
  assert.ok(physical.includes("--host-resolver-rules=MAP passkeys.example.test 127.0.0.1"));
  assert.ok(physical.includes("--ignore-certificate-errors-spki-list=test-pin"));
  assert.equal(physical.includes("--ignore-certificate-errors"), false);
  assert.ok(chromeArguments({ ...input, physical: false }).includes("--headless=new"));
});

test("physical metadata is bounded and reports require absolute paths", () => {
  const parsed = options([...required, "--physical-key", "--key-model", "Security Key C NFC",
    "--key-firmware", "5.7.4", "--key-transport", "usb", "--report-file", "/tmp/new-report.json"]);
  assert.equal(parsed.get("--key-model"), "Security Key C NFC");
  assert.equal(parsed.get("--report-file"), "/tmp/new-report.json");
  assert.throws(() => options([...required, "--report-file", "/tmp/report.json"]));
  assert.throws(() => options([...required, "--physical-key", "--report-file", "relative.json"]));
  assert.throws(() => options([...required, "--physical-key", "--key-model", "a".repeat(121)]));
  assert.throws(() => options([...required, "--physical-key", "--key-model", "line\nbreak"]));
});

test("removed-key rejection requires a fresh actual server finish response", () => {
  const old = [{ path: "/sign-in/finish", status: 400 }];
  assert.throws(() => requireOutcome(old, 1, "/sign-in/finish", 400));
  assert.throws(() => requireOutcome([...old, { path: "/sign-in/start", status: 200 }],
    1, "/sign-in/finish", 400));
  assert.throws(() => requireOutcome([...old, { path: "/sign-in/finish", status: 200 }],
    1, "/sign-in/finish", 400));
  assert.doesNotThrow(() => requireOutcome([...old, { path: "/sign-in/finish", status: 400 }],
    1, "/sign-in/finish", 400));
});
