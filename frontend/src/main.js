import Keycloak from "keycloak-js";

const API_BASE = "http://localhost:8000";
const KC = new Keycloak({
  url: "http://localhost:8080",
  realm: "demo",
  clientId: "frontend", // dein PKCE/SSO Client
});

let tokenSource = "none"; // "keycloak" | "local" | "none"
let accessToken = null;

function setOut(text) {
  document.getElementById("out").textContent = text;
}

async function callApi(path) {
  if (!accessToken) {
    setOut("No token yet. Please login first.");
    return;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const body = await res.text();
  setOut(`HTTP ${res.status}\n${body}`);
}

async function init() {
  const el = document.getElementById("app");

  const authenticated = await KC.init({
    onLoad: "check-sso",
    pkceMethod: "S256",
  });

  if (authenticated) {
    tokenSource = "keycloak";
    accessToken = KC.token;
    window.__TOKEN__ = accessToken;
  }

  el.innerHTML = `
    <h1>Login</h1>

    <section style="border:1px solid #ccc; padding:12px; margin-bottom:12px;">
      <h2>SSO (Keycloak)</h2>
      <div>Authenticated: <b>${authenticated}</b></div>
      <button id="btnSsoLogin">Login via Keycloak</button>
      <button id="btnSsoLogout">Logout Keycloak</button>
    </section>

    <section style="border:1px solid #ccc; padding:12px; margin-bottom:12px;">
      <h2>Local Login (ohne Keycloak)</h2>
      <input id="email" placeholder="email" style="display:block; margin:6px 0; width: 320px;" />
      <input id="password" placeholder="password" type="password" style="display:block; margin:6px 0; width: 320px;" />
      <button id="btnLocalLogin">Login lokal</button>
      <button id="btnLocalLogout">Logout lokal</button>
    </section>

    <section style="border:1px solid #ccc; padding:12px; margin-bottom:12px;">
      <h2>API</h2>
      <div>Token source: <b id="tokenSource">${tokenSource}</b></div>
      <button id="btnMe">GET /api/me</button>
      <button id="btnAdmin">GET /api/admin/ping</button>
    </section>

    <pre id="out" style="white-space:pre-wrap; border:1px solid #eee; padding:12px;"></pre>
  `;

  document.getElementById("btnSsoLogin").onclick = () => KC.login();
  document.getElementById("btnSsoLogout").onclick = () =>
    KC.logout({ redirectUri: "http://localhost:5173" });

  document.getElementById("btnLocalLogin").onclick = async () => {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    const res = await fetch(`${API_BASE}/auth/local/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const text = await res.text();
    if (!res.ok) {
      setOut(`Local login failed (HTTP ${res.status}):\n${text}`);
      return;
    }

    const data = JSON.parse(text);
    accessToken = data.access_token;
    tokenSource = "local";
    document.getElementById("tokenSource").textContent = tokenSource;

    setOut("Local login OK. Token received.");
  };

  document.getElementById("btnLocalLogout").onclick = () => {
    accessToken = null;
    tokenSource = "none";
    document.getElementById("tokenSource").textContent = tokenSource;
    setOut("Local token cleared.");
  };

  document.getElementById("btnMe").onclick = async () => {
    // Keycloak Token refreshen, wenn es Keycloak-source ist
    if (tokenSource === "keycloak") {
      await KC.updateToken(30);
      accessToken = KC.token;
    }
    await callApi("/api/me");
  };

  document.getElementById("btnAdmin").onclick = async () => {
    if (tokenSource === "keycloak") {
      await KC.updateToken(30);
      accessToken = KC.token;
    }
    await callApi("/api/admin/ping");
  };
}

init().catch((e) => {
  console.error(e);
  document.getElementById("app").textContent = String(e);
});
window.__TOKEN__ = accessToken;
