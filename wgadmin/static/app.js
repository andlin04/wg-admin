// wg-admin page script (was inline in index.html; a file so the Content-Security-Policy can forbid inline scripts).
import { api, icon, mount, setOnAuth } from "./ui.js";
const $ = (id) => document.getElementById(id);
// Theme (same as the portal's): dark unless the OS asks for light; the button overrides it, kept per browser.
const isDark = () => { const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : !matchMedia("(prefers-color-scheme: light)").matches; };
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  $("themebtn").replaceChildren(icon(isDark() ? "sun" : "moon"));
  $("themebtn").title = isDark() ? "Switch to light theme" : "Switch to dark theme";
}
let savedTheme = null;
try { savedTheme = localStorage.getItem("theme"); } catch { /* storage blocked: follow the OS */ }
applyTheme(savedTheme);
$("themebtn").onclick = () => {
  const next = isDark() ? "light" : "dark";
  try { localStorage.setItem("theme", next); } catch { /* not remembered */ }
  applyTheme(next);
};
setOnAuth(() => { if ($("login").hidden) showLogin(); });  // signed out: the login form, never a reload
function showLogin() {
  $("vpnmount").replaceChildren();
  $("login").hidden = false;
  $("acct").hidden = true;
  $("logout").hidden = $("acctbtn").hidden = true;
  $("lcodebox").hidden = true;
  $("lcode").value = "";
  $("who").textContent = "";
  $("lname").focus();
}
async function start() {
  let me;
  try { me = await api("api/me"); } catch { showLogin(); return; }
  $("login").hidden = true;
  $("who").textContent = me.user;
  $("host").textContent = me.host || "";
  $("logout").hidden = $("acctbtn").hidden = me.via !== "local";
  mount($("vpnmount"));
  if (me.must_enrol) openAcct();  // the role needs an authenticator: the server allows only this until it is set up
}
$("login").onsubmit = async (e) => {
  e.preventDefault();
  $("lmsg").textContent = "";
  try {
    const r = await api("api/login", { method: "POST", body: JSON.stringify({ name: $("lname").value.trim(), password: $("lpw").value, code: $("lcode").value.trim() }) });
    if (r.code_required) { $("lcodebox").hidden = false; $("lcode").focus(); return; }
    $("lpw").value = $("lcode").value = "";
    start();
  } catch (x) { $("lmsg").textContent = x.message; }
};
$("logout").onclick = async () => { await api("api/logout", { method: "POST" }).catch(() => {}); showLogin(); };

// Account: authenticator status, set-up (QR + key, confirmed by a code), recovery codes, turn off.
function acctState(s) {
  $("acctstate").textContent = s.enabled
    ? `On: sign-in asks for a code from the authenticator app. ${s.recovery_left} recovery code(s) left.`
    : "Off: sign-in needs only the password. Turn it on to also ask for a code from an authenticator app.";
  $("acctstart").textContent = s.enabled ? "Replace authenticator" : "Set up authenticator";
  $("acctoffbtn").hidden = !s.enabled;
  $("acctoff").hidden = true;
}
async function openAcct() {
  const open = $("acct").hidden;
  $("acct").hidden = !open;
  $("acctbtn").setAttribute("aria-expanded", String(open));
  if (!open) return;
  $("acctsetup").hidden = $("acctrec").hidden = $("acctpwform").hidden = true;
  $("acctpwbtn").setAttribute("aria-expanded", "false");
  $("acctmsg").textContent = "";
  try { acctState(await api("api/account/totp")); } catch (x) { $("acctmsg").textContent = x.message; }
}
$("acctbtn").onclick = openAcct;
$("acctclose").onclick = () => { $("acct").hidden = false; openAcct(); };
$("acctstart").onclick = async () => {
  $("acctmsg").textContent = "";
  $("acctrec").hidden = true;
  try {
    const d = await api("api/account/totp/setup", { method: "POST" });
    $("acctqr").hidden = !d.qr;
    if (d.qr) $("acctqr").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(d.qr);
    $("acctsecret").textContent = "Key: " + d.secret.replace(/(.{4})/g, "$1 ").trim();
    $("acctcode").value = "";
    $("acctsetup").hidden = false;
    $("acctcode").focus();
  } catch (x) { $("acctmsg").textContent = x.message; }
};
$("acctconfirm").onclick = async () => {
  try {
    const d = await api("api/account/totp/confirm", { method: "POST", body: JSON.stringify({ code: $("acctcode").value.trim() }) });
    $("acctsetup").hidden = true;
    $("acctreclist").textContent = d.recovery.join("\n");
    $("acctrec").hidden = false;
    acctState(d);
    $("acctmsg").textContent = "Authenticator on.";
  } catch (x) { $("acctmsg").textContent = x.message; }
};
$("acctoffbtn").onclick = () => { $("acctoff").hidden = false; $("acctpw").focus(); };
$("acctoffgo").onclick = async () => {
  try {
    acctState(await api("api/account/totp/disable", { method: "POST", body: JSON.stringify({ password: $("acctpw").value, code: $("acctoffcode").value.trim() }) }));
    $("acctpw").value = $("acctoffcode").value = "";
    $("acctmsg").textContent = "Authenticator off.";
  } catch (x) { $("acctmsg").textContent = x.message; }
};
// Own password (api/account/password): the old one again; the server ends every session, so back to the login.
$("acctpwbtn").onclick = () => {
  const open = $("acctpwform").hidden;
  $("acctpwform").hidden = !open;
  $("acctpwbtn").setAttribute("aria-expanded", String(open));
  if (open) $("acctold").focus();
};
$("acctpwform").onsubmit = async (e) => {
  e.preventDefault();
  $("acctmsg").textContent = "";
  if ($("acctnew").value !== $("acctnew2").value) { $("acctmsg").textContent = "The new passwords don't match."; $("acctnew2").focus(); return; }
  try {
    await api("api/account/password", { method: "POST", body: JSON.stringify({ old: $("acctold").value, new: $("acctnew").value }) });
    $("acctold").value = $("acctnew").value = $("acctnew2").value = "";
    showLogin();
    $("lmsg").textContent = "Password changed: sign in with the new one.";
  } catch (x) { $("acctmsg").textContent = x.message; }
};
start();
