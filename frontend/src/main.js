import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: "http://localhost:8080",
  realm: "demo",
  clientId: "frontend",
});

async function init() {
  const el = document.getElementById("app");

  // check-sso: lädt Seite ohne sofortigen Redirect; login-required würde sofort redirecten
  const authenticated = await keycloak.init({
    onLoad: "check-sso",
    pkceMethod: "S256",
  });

  el.innerHTML = `
    <h1>Frontend SSO (Keycloak)</h1>
    <div>Authenticated: <b>${authenticated}</b></div>
    <button id="login">Login</button>
    <button id="logout">Logout</button>
    <button id="callMe">Call /api/me</button>
    <button id="callAdmin">Call /api/admin/ping</button>
    <pre id="out"></pre>
  `;

  document.getElementById("login").onclick = () => keycloak.login();
  document.getElementById("logout").onclick = () =>
    keycloak.logout({ redirectUri: "http://localhost:5173" });

  async function callApi(path) {
    // Token ggf. refreshen (30s Puffer)
    await keycloak.updateToken(30);

    const res = await fetch(`http://localhost:8000${path}`, {
      headers: {
        Authorization: `Bearer ${keycloak.token}`,
      },
    });

    const text = await res.text();
    document.getElementById("out").textContent =
      `HTTP ${res.status}\n` + text;
  }

  document.getElementById("callMe").onclick = () => callApi("/api/me");
  document.getElementById("callAdmin").onclick = () => callApi("/api/admin/ping");
}

init().catch(console.error);
