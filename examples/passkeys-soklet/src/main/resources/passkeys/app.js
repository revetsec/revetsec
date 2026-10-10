"use strict";

const page = document.body;
const csrf = page.dataset.csrf;
const status = document.getElementById("status");
const authenticated = page.dataset.authenticated === "true";
document.getElementById("login").hidden = authenticated;
document.getElementById("account").hidden = !authenticated;

function report(message) {
  status.textContent = message;
}

async function call(path, extraHeaders = {}, body = null) {
  const headers = { "X-CSRF-Token": csrf, ...extraHeaders };
  if (body !== null) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin", cache: "no-store", headers,
    body: body === null ? null : JSON.stringify(body)
  });
  if (!response.ok) throw new Error((await response.text()).slice(0, 160));
  return response;
}

async function ceremony(startPath, finishPath, creation) {
  if (!window.PublicKeyCredential ||
      !PublicKeyCredential.parseCreationOptionsFromJSON ||
      !PublicKeyCredential.parseRequestOptionsFromJSON) {
    report("This browser does not support the required WebAuthn JSON API.");
    return;
  }
  try {
    const started = await (await call(startPath)).json();
    const options = creation
      ? PublicKeyCredential.parseCreationOptionsFromJSON(started.publicKey)
      : PublicKeyCredential.parseRequestOptionsFromJSON(started.publicKey);
    const credential = creation
      ? await navigator.credentials.create({ publicKey: options })
      : await navigator.credentials.get({ publicKey: options });
    if (!credential || !credential.toJSON) throw new Error("Browser ceremony was cancelled.");
    report(await (await call(finishPath, { "X-Ceremony-Id": started.ceremonyId },
      credential.toJSON())).text());
    if (finishPath === "/sign-in/finish") window.location.reload();
  } catch (error) {
    if (error instanceof DOMException && (error.name === "NotAllowedError" ||
        error.name === "AbortError")) report("Browser ceremony cancelled.");
    else report(error instanceof Error ? error.message : "Operation failed.");
  }
}

async function action(work) {
  try { await work(); }
  catch (error) { report(error instanceof Error ? error.message : "Operation failed."); }
}

document.getElementById("access-login").addEventListener("click", () => action(async () => {
  const key = document.getElementById("access").value;
  await call("/access-login", { "X-Demo-Access-Key": key });
  window.location.reload();
}));
document.getElementById("sign-in").addEventListener("click", () =>
  ceremony("/sign-in/start", "/sign-in/finish", false));
document.getElementById("register").addEventListener("click", () =>
  ceremony("/register/start", "/register/finish", true));
document.getElementById("reauth").addEventListener("click", () =>
  ceremony("/reauth/start", "/reauth/finish", false));
document.getElementById("sensitive").addEventListener("click", () => action(async () =>
  report(await (await call("/sensitive")).text())));
document.getElementById("logout").addEventListener("click", () => action(async () => {
  await call("/logout");
  window.location.reload();
}));
document.getElementById("list").addEventListener("click", () => action(async () => {
  const ids = (await (await call("/credentials/list")).json()).credentialIds;
  const list = document.getElementById("credentials");
  list.replaceChildren();
  for (const id of ids) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = `${id.slice(0, 12)}… `;
    const remove = document.createElement("button");
    remove.textContent = "Remove";
    remove.addEventListener("click", () => action(async () => {
      report(await (await call("/credentials/remove", { "X-Credential-Id": id })).text());
      item.remove();
    }));
    item.append(label, remove);
    list.append(item);
  }
  if (ids.length === 0) report("No passkeys registered.");
}));
