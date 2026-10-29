// wg-admin UI (map vpn-standalone): peers, profiles and the health map of this WireGuard server.
// One module for both homes: the portal's VPN tab imports it from /vpn/ui.js (nginx proxy, portal login), and
// vpn1's own page (index.html) mounts it after a local sign-in. API paths are relative to where this file lives.
const BASE = new URL(".", import.meta.url).pathname;
let root = null, onAuth = () => location.reload();
let PROFILES = [], SCHEDULES = [], tagFilter = "", info = null;
const PICKED = new Set();  // device names ticked for "Email owners"

const $ = (id) => root.querySelector("#" + id);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
const ICONS = {
  cloud: '<path d="M7 18h10a4 4 0 0 0 .7-7.94A6 6 0 0 0 6.1 9.5 4.25 4.25 0 0 0 7 18z"/>',
  shield: '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  box: '<path d="M21 8l-9-5-9 5 9 5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>',
  device: '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M11 17h2"/>',
};
function icon(name, cls) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", "icon" + (cls ? " " + cls : ""));
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name];
  return s;
}
function ago(seconds) {
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600);
  return d ? `${d}d ${h}h` : `${h}h ${Math.floor((seconds % 3600) / 60)}m`;
}
const whenAt = (t) => t ? new Date(t * 1000).toLocaleString() : "never";

// The standalone page sets this before its first api() call: the default (reload) suits only the portal, where a
// reload brings up the portal login; without it a signed-out standalone page reloads forever (2026-10-29).
export function setOnAuth(fn) { onAuth = fn; }

export async function api(path, opts = {}) {
  const res = await fetch(BASE + path, { headers: { "Content-Type": "application/json" }, ...opts });
  const type = res.headers.get("content-type") || "";
  if (!type.includes("json")) {  // the portal's proxy sent its login page: session ended
    if (res.redirected || res.status === 401) onAuth();
    throw new Error(`HTTP ${res.status}`);
  }
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) onAuth();
  if (!res.ok) {
    // FastAPI field errors come as a list: name the field instead of a bare status code
    const d = body.detail;
    const msg = typeof d === "string" ? d : Array.isArray(d) && d.length ? d.map((e) => `${(e.loc || []).slice(1).join(".") || "input"}: ${e.msg}`).join("; ") : "";
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return body;
}

const tagList = (text) => text.split(/[\s,]+/).map((t) => t.trim().toLowerCase()).filter(Boolean);
const profDesc = (name) => (PROFILES.find((p) => p.name === name) || {}).description || "";
const bytes = (n) => n < 1e6 ? `${Math.round(n / 1e3)} kB` : n < 1e9 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e9).toFixed(2)} GB`;
const peerPath = (name) => "api/peers/" + encodeURIComponent(name);

// Static markup only (no data): the forms and containers the functions below fill.
const MARKUP = `
<div class="page">
  <div class="pagehead"><div><h1 id="vpn-h">VPN</h1></div>
    <div class="userrow-actions">
      <button class="btn sm" id="vpnaddbtn" type="button" aria-expanded="false" aria-controls="vpnform">Add a device</button>
      <button class="btn sm vpnadmin" id="vpnbulkbtn" type="button" aria-expanded="false" aria-controls="vpnbform">Add several</button>
      <button class="btn sm" type="button" id="vpnreload">Reload</button></div></div>
  <div class="vpngrid">
  <aside class="vpnhealth vpnadmin" aria-labelledby="vpnh-h">
    <div class="vpnhhead"><h2 id="vpnh-h">Health</h2>
      <button class="btn sm" type="button" id="vpnhrun">Run checks</button></div>
    <p class="meta" id="vpnhwhen" role="status"></p>
    <div class="topo vpnchain" id="vpnchain"><div class="nodata">Loading…</div></div>  </aside>
  <div class="vpnmain">
  <!-- Tabs in set-up order (owner 2026-10-27): profiles and schedules first, so a new device can pick them -->
  <div class="seg vpnseg" role="group" aria-label="View">
    <button type="button" class="segbtn vpnadmin" data-vview="profiles" aria-pressed="false">Connection profiles</button>
    <button type="button" class="segbtn" data-vview="schedules" aria-pressed="false">Schedules</button>
    <button type="button" class="segbtn" data-vview="devices" aria-pressed="true">Devices</button>
    <button type="button" class="segbtn vpnadmin" data-vview="server" aria-pressed="false">Server settings</button>
    <button type="button" class="segbtn vpnadmin" data-vview="groups" aria-pressed="false">Groups</button>
    <button type="button" class="segbtn vpnadmin" data-vview="users" aria-pressed="false">Users</button></div>
  <!-- Groups + Users (map wg-admin-groups): admins only; the server refuses everyone else -->
  <div class="vpnview" id="vpnvgroups" hidden>
  <div class="pagehead vpnphead"><div><h2>Groups</h2><p>Devices grouped for group admins. A group admin manages only
    its groups' devices, with the connection profiles and schedules linked here.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpngadd" type="button">Add a group</button></div></div>
  <form id="vpngform" class="factform" hidden>
    <h2 id="vpngformh">Add a group</h2>
    <label for="vpngname">Name</label>
    <input class="input" id="vpngname" maxlength="16" autocomplete="off" pattern="[a-z0-9][a-z0-9\\-]{0,15}" placeholder="family" autocapitalize="none" spellcheck="false" required>
    <label for="vpngdesc">Description</label>
    <input class="input" id="vpngdesc" maxlength="160" autocomplete="off">
    <fieldset class="vpnfs"><legend>Connection profiles its group admins may use</legend><div class="vpndays" id="vpngprofs"></div></fieldset>
    <fieldset class="vpnfs"><legend>Schedules its group admins may use</legend><div class="vpndays" id="vpngscheds"></div></fieldset>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpngcancel">Cancel</button> <span id="vpngmsg" class="meta" role="status"></span></div>
  </form>
  <div id="vpngbox"><div class="nodata">Loading…</div></div>
  </div>
  <div class="vpnview" id="vpnvusers" hidden>
  <div class="pagehead vpnphead"><div><h2>Users</h2><p>Web UI accounts. Any change of role, groups, state or password
    signs that user out at once. The default admin keeps its role and can't be disabled or deleted.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnuadd" type="button">Add a user</button></div></div>
  <form id="vpnuform" class="factform" hidden>
    <h2 id="vpnuformh">Add a user</h2>
    <label for="vpnuname">Name</label>
    <input class="input" id="vpnuname" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" required>
    <label for="vpnupw" id="vpnupwl">Password (at least 12 characters)</label>
    <input class="input" id="vpnupw" type="password" maxlength="200" minlength="12" autocomplete="new-password">
    <label for="vpnurole">Role</label>
    <select class="input" id="vpnurole"><option value="group-admin">Group admin: devices of its groups</option><option value="admin">Admin: everything</option></select>
    <fieldset class="vpnfs" id="vpnugfs"><legend>Groups</legend><div class="vpndays" id="vpnugroups"></div>
      <p class="hint" id="vpnunogroups" hidden>No groups yet: the user sees no devices until you add a group (Groups tab) and tick it here.</p></fieldset>
    <label for="vpnusched">Sign-in hours (a schedule; empty = any time)</label>
    <select class="input" id="vpnusched"></select>
    <label for="vpnuexp">Expires after (optional)</label>
    <input class="input" id="vpnuexp" type="date">
    <label class="hint"><input type="checkbox" id="vpnudis"> Disabled</label>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnucancel">Cancel</button> <span id="vpnumsg" class="meta" role="status"></span></div>
  </form>
  <div id="vpnubox"><div class="nodata">Loading…</div></div>
  <fieldset class="vpnfs"><legend>Require an authenticator app for</legend>
    <div class="vpndays"><label><input type="checkbox" id="vpnpoladmin"> admins</label>
      <label><input type="checkbox" id="vpnpolgroup"> group admins</label></div>
    <p class="hint">Accounts of a required role without one can only set it up (Account) until they have it.</p>
    <div><button class="btn sm" type="button" id="vpnpolsave">Save</button> <span id="vpnpolmsg" class="meta" role="status"></span></div></fieldset>
  </div>
  <div class="vpnview" id="vpnvdevices">
  <form id="vpnform" class="factform" hidden>
    <h2>Add a device</h2>
    <label for="vpnname">Name (owner and device)</label>
    <input class="input" id="vpnname" maxlength="31" autocomplete="off" pattern="[a-z0-9][a-z0-9\\-]{0,30}" title="lowercase letters, digits and dashes, e.g. anna-phone" placeholder="anna-phone" autocapitalize="none" spellcheck="false" required>
    <label for="vpngroup">Group</label>
    <select class="input" id="vpngroup"></select>
    <label for="vpnprof">Connection profile</label>
    <select class="input" id="vpnprof"></select>
    <p class="hint" id="vpnprofhint"></p>
    <label for="vpnaddsched">Schedule (optional)</label>
    <select class="input" id="vpnaddsched"></select>
    <label for="vpntags">Tags (optional, comma-separated: groups for the filter)</label>
    <input class="input" id="vpntags" maxlength="180" autocomplete="off" placeholder="family, phones" autocapitalize="none" spellcheck="false">
    <label for="vpnemail">Owner email (optional: for notices)</label>
    <input class="input" id="vpnemail" type="email" maxlength="254" autocomplete="off" placeholder="anna@example.org" autocapitalize="none" spellcheck="false">
    <div><button class="btn primary sm" type="submit">Create</button>
      <button class="btn ghost sm" type="button" id="vpncancel">Cancel</button> <span id="vpnmsg" class="meta" role="status"></span></div>
  </form>
  <form id="vpnbform" class="factform" hidden>
    <h2>Add several devices</h2>
    <label for="vpnblines">One device per line: name, profile, tags, owner email (profile empty = split; tags separated by spaces)</label>
    <textarea class="input mono" id="vpnblines" rows="6" maxlength="10000" required autocapitalize="none" spellcheck="false"
      placeholder="anna-phone, full, family, anna@example.org&#10;anna-pc, split, family laptops, anna@example.org&#10;lab-pi, lab"></textarea>
    <p class="hint">Every line is checked before any device is created (up to 50). Hand each device its QR or package afterwards.</p>
    <div><button class="btn primary sm" type="submit">Create all</button>
      <button class="btn ghost sm" type="button" id="vpnbcancel">Cancel</button> <span id="vpnbmsg" class="meta" role="status"></span></div>
  </form>
  <section class="userpanel" id="vpnqrbox" hidden aria-live="polite"></section>
  <div class="vpnlisthead"><input class="input vpnq" id="vpndq" type="search" placeholder="Filter devices" aria-label="Filter devices" autocomplete="off" spellcheck="false">
    <span class="userrow-actions" id="vpndbar"></span></div>
  <div id="vpnbox"><div class="nodata">Loading…</div></div>
  </div>
  <div class="vpnview" id="vpnvprofiles" hidden>
  <div class="pagehead vpnphead"><div><h2 id="vpnp-h">Connection profiles</h2><p>Client routes and DNS for a group of devices. The server's
    firewall enforces them: a device reaches only its profile's routes, and only its DNS servers.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnpaddbtn" type="button" aria-expanded="false" aria-controls="vpnpform">Add a profile</button></div></div>
  <form id="vpnpform" class="factform" hidden>
    <h2 id="vpnpformh">Add a profile</h2>
    <div class="userrow-actions" id="vpnptpl"><span class="meta">Start from:</span>
      <button class="btn sm" type="button" data-tpl="lan">LAN only</button>
      <button class="btn sm" type="button" data-tpl="full">Full tunnel</button>
      <button class="btn sm" type="button" data-tpl="hosts">Host list</button>
      <button class="btn sm" type="button" data-tpl="locked">Full tunnel, listed hosts only</button></div>
    <label for="vpnpname">Name</label>
    <input class="input" id="vpnpname" maxlength="16" autocomplete="off" pattern="[a-z0-9][a-z0-9\\-]{0,15}" title="lowercase letters, digits and dashes, e.g. lab-only" placeholder="lab-only" autocapitalize="none" spellcheck="false" required>
    <label for="vpnproutes">Routes through the tunnel (CIDRs, comma or one per line)</label>
    <textarea class="input" id="vpnproutes" rows="3" maxlength="1000" required placeholder="192.168.4.0/24" autocapitalize="none" spellcheck="false"></textarea>
    <label for="vpnpdns">DNS (addresses and search domain; empty = the device's own DNS)</label>
    <input class="input" id="vpnpdns" maxlength="300" autocomplete="off" autocapitalize="none" spellcheck="false">
    <label class="hint"><input type="checkbox" id="vpnpv6"> IPv6 through the tunnel</label>
    <p class="hint">On: devices also get an fd66:66:: address and the server forwards their IPv6 to the IPv6 routes (add ::/0).
      Off: IPv6 from these devices is dropped; an IPv6 route like ::/0 then only stops IPv6 leaking past the tunnel.
      Works beyond the tunnel only when the server has an IPv6 upstream (see the server in Health).</p>
    <label for="vpnpallow">Allowed destinations (optional firewall rules, one per line)</label>
    <textarea class="input" id="vpnpallow" rows="3" maxlength="1000" placeholder="192.168.0.10/32&#10;192.168.0.20/32 tcp 443" autocapitalize="none" spellcheck="false"></textarea>
    <p class="hint">Empty: devices reach everything in their routes. Filled: the server lets them reach only these
      (<code>CIDR</code> or <code>CIDR tcp|udp PORT[-PORT]</code>) plus the profile's DNS servers; everything else is
      dropped, internet included. Only traffic inside the routes reaches the server: use a full tunnel to block the internet.</p>
    <label for="vpnpdesc">Description</label>
    <input class="input" id="vpnpdesc" maxlength="160" autocomplete="off" placeholder="Lab VLAN only">
    <p class="hint" id="vpnphint" hidden></p>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnpcancel">Cancel</button> <span id="vpnpmsg" class="meta" role="status"></span></div>
  </form>
  <div class="vpnlisthead"><input class="input vpnq" id="vpnpq" type="search" placeholder="Name, route or IP address" aria-label="Filter connection profiles" title="An IP address finds the profiles whose devices can reach it" autocomplete="off" spellcheck="false"></div>
  <div id="vpnpbox"></div>
  </div>
  <div class="vpnview" id="vpnvschedules" hidden>
  <div class="pagehead vpnphead"><div><h2 id="vpnsc-h">Schedules</h2><p>When devices may connect. The server switches a
    device with a schedule on and off every minute (the server's local time). A manual switch holds until the schedule's
    next change.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnscadd" type="button" aria-expanded="false" aria-controls="vpnscform">Add a schedule</button></div></div>
  <form id="vpnscform" class="factform" hidden>
    <h2 id="vpnscformh">Add a schedule</h2>
    <label for="vpnscname">Name</label>
    <input class="input" id="vpnscname" maxlength="16" autocomplete="off" pattern="[a-z0-9][a-z0-9\\-]{0,15}" title="lowercase letters, digits and dashes, e.g. school-days" placeholder="school-days" autocapitalize="none" spellcheck="false" required>
    <label for="vpnscgroup" class="vpnscnew">For group (its group admins can use and edit it)</label>
    <select class="input vpnscnew" id="vpnscgroup"></select>
    <label for="vpnscdesc">Description</label>
    <input class="input" id="vpnscdesc" maxlength="160" autocomplete="off" placeholder="Weekdays after school">
    <fieldset class="vpnfs"><legend>Weekly hours (none = no weekly hours)</legend>
      <div id="vpnscwins"></div>
      <div><button class="btn sm" type="button" id="vpnscwinadd">Add hours</button></div></fieldset>
    <fieldset class="vpnfs"><legend>Calendar dates, on all day (a single day: leave "to" empty)</legend>
      <div id="vpnscdlist"></div>
      <div><button class="btn sm" type="button" id="vpnscdadd">Add a date</button></div></fieldset>
    <label for="vpnscfrom">Valid from (optional)</label>
    <input class="input" id="vpnscfrom" type="date">
    <label for="vpnscexp">Expires after (optional: off from the next day)</label>
    <input class="input" id="vpnscexp" type="date">
    <p class="hint">On = between valid from and expires, and inside a weekly window or on a calendar date. No hours
      and no dates: on the whole valid period (use it for an expiry alone). Overnight windows like 22:00-06:00 work.</p>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnsccancel">Cancel</button> <span id="vpnscmsg" class="meta" role="status"></span></div>
  </form>
  <div class="vpnlisthead"><input class="input vpnq" id="vpnscq" type="search" placeholder="Filter schedules" aria-label="Filter schedules" autocomplete="off" spellcheck="false">
    <span class="meta" id="vpnsctime"></span></div>
  <div id="vpnscbox"></div>
  </div>
  <div class="vpnview" id="vpnvserver" hidden>
  <div class="pagehead vpnphead"><div><h2 id="vpns-h">Server</h2><p>WireGuard settings on the server.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnsedit" type="button" aria-expanded="false" aria-controls="vpnsform">Edit</button>
      <button class="btn sm" id="vpnreboot" type="button">Reboot</button></div></div>
  <p id="vpnrebootmsg" class="meta" role="status"></p>
  <form id="vpnsform" class="factform" hidden>
    <h2>Edit server settings</h2>
    <label for="vpnsep">Endpoint (host:port the devices dial: public name or address, forwarded port)</label>
    <input class="input" id="vpnsep" maxlength="300" autocomplete="off" placeholder="vpn.example.org:51820" autocapitalize="none" spellcheck="false" required>
    <label for="vpnsport">Listen port on the server (UDP)</label>
    <input class="input" id="vpnsport" type="number" min="1" max="65535" required>
    <label for="vpnska">Client keepalive (seconds, 0 = off)</label>
    <input class="input" id="vpnska" type="number" min="0" max="3600" required>
    <p class="hint">Endpoint or keepalive: every device's config is rewritten; each must import its new config (QR or
      package), marked "re-import" in the device list. Listen port: the router's port forward must point to the new port.</p>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnscancel">Cancel</button> <span id="vpnsmsg" class="meta" role="status"></span></div>
  </form>
  <div id="vpnsbox"><div class="nodata">Loading…</div></div>
  <!-- Network (map vpn-routing-mode): NAT or routed IPv4, incoming and transit interface -->
  <div class="pagehead vpnphead"><div><h2 id="vpnn-h">Network</h2><p>How device traffic leaves the server.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnnedit" type="button" aria-expanded="false" aria-controls="vpnnform">Edit</button></div></div>
  <form id="vpnnform" class="factform" hidden>
    <h2>Edit network</h2>
    <label for="vpnnmode">Mode</label>
    <select class="input" id="vpnnmode"><option value="nat">NAT: devices appear as the server</option>
      <option value="route">Route: devices keep their 10.66.0.N</option></select>
    <label for="vpnnin">Incoming VPN connections (and the server's own traffic)</label>
    <select class="input" id="vpnnin"></select>
    <label for="vpnnout" class="vpnnroute">Device traffic out (transit; same interface allowed)</label>
    <select class="input vpnnroute" id="vpnnout"></select>
    <label for="vpnngw" class="vpnngw">Transit gateway (next hop on that interface)</label>
    <input class="input vpnngw" id="vpnngw" maxlength="15" autocomplete="off" placeholder="192.168.5.1" spellcheck="false">
    <p class="hint" id="vpnnhint"></p>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnncancel">Cancel</button> <span id="vpnnmsg" class="meta" role="status"></span></div>
  </form>
  <div id="vpnnbox"><div class="nodata">Loading…</div></div>
  <!-- Firewall (owner 2026-10-27: readable instead of raw nftables): read from vpn1's live ruleset -->
  <div class="pagehead vpnphead"><div><h2 id="vpnfw-h">Firewall</h2><p>What the server's firewall lets each connection
    profile's devices reach, read from the live rules. Edit rules: change a profile's allowed destinations here.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnfwreload" type="button">Reload</button>
      <button class="btn sm" id="vpnrules" type="button" aria-expanded="false" aria-controls="vpnrulesbox">Raw rules</button></div></div>
  <div id="vpnfwbox"><div class="nodata">Loading…</div></div>
  <pre class="mono vpnrules" id="vpnrulesbox" hidden></pre>
  <div class="pagehead vpnphead"><div><h2 id="vpnm-h">Mail</h2><p>Sender for notices to device owners. Notices hold no
    keys: device name, what changed, ask the administrator for the new config.</p></div>
    <div class="userrow-actions"><button class="btn sm" id="vpnmedit" type="button" aria-expanded="false" aria-controls="vpnmform">Edit</button>
      <button class="btn sm" id="vpnmtest" type="button">Send test mail</button></div></div>
  <form id="vpnmform" class="factform" hidden>
    <h2>Edit mail settings</h2>
    <label for="vpnmfrom">From address</label>
    <input class="input" id="vpnmfrom" type="email" maxlength="254" autocomplete="off" placeholder="vpn@example.org" autocapitalize="none" spellcheck="false" required>
    <label for="vpnmhost">SMTP relay host</label>
    <input class="input" id="vpnmhost" maxlength="253" autocomplete="off" placeholder="smtp.example.org" autocapitalize="none" spellcheck="false" required>
    <label for="vpnmport">Port</label>
    <input class="input" id="vpnmport" type="number" min="1" max="65535" required>
    <label for="vpnmsec">Security</label>
    <select class="input" id="vpnmsec"><option value="none">none (LAN relay only)</option><option value="starttls">STARTTLS (usually port 587)</option><option value="ssl">SSL/TLS (usually port 465)</option></select>
    <label for="vpnmuser">User (empty = no login)</label>
    <input class="input" id="vpnmuser" maxlength="200" autocomplete="off" autocapitalize="none" spellcheck="false">
    <label for="vpnmpw">Password (empty = keep the stored one; never shown)</label>
    <input class="input" id="vpnmpw" type="password" maxlength="500" autocomplete="new-password">
    <label class="hint"><input type="checkbox" id="vpnmpwclear"> Clear the stored password</label>
    <div><button class="btn primary sm" type="submit">Save</button>
      <button class="btn ghost sm" type="button" id="vpnmcancel">Cancel</button> <span id="vpnmmsg" class="meta" role="status"></span></div>
  </form>
  <p class="meta" id="vpnmtmsg" role="status"></p>
  <div id="vpnmbox"><div class="nodata">Loading…</div></div>
  </div>
  </div>
  <!-- Info box (owner 2026-10-27): what this is + short how-tos, right of everything -->
  <aside class="vpnhealth vpninfo" aria-labelledby="vpni-h">
    <h2 id="vpni-h">About</h2>
    <p class="meta">WireGuard on the server (wg-admin). One peer per device; it reaches only its profile's routes, not the server
      or other devices.</p>
    <h2>How to</h2>
    <ul class="meta">
      <li><strong>1. Connection profiles:</strong> what a device reaches; filter by an IP to find who reaches it. Changing it needs a re-import on the device.</li>
      <li><strong>2. Schedules (optional):</strong> switch access by themselves; a manual switch holds until the next change.</li>
      <li><strong>3. Devices:</strong> Add a device with a profile and schedule, then scan the QR in the WireGuard app (or send the .zip).</li>
      <li><strong>Slider:</strong> access on/off; the setup stays.</li>
      <li><strong>re-import:</strong> config changed: show the QR again.</li>
      <li><strong>Revoke:</strong> removes the device for good.</li>
      <li><strong>Server settings:</strong> endpoint, port, mail, and what the firewall lets each profile reach.</li>
    </ul>
  </aside>
  </div>
</div>`;

function showQr(name, note) {
  const box = $("vpnqrbox"), img = el("img", "vpnqr");
  // unique URL: the in-page image cache ignores no-store and showed an old QR after a profile change (2026-10-27)
  img.src = BASE + peerPath(name) + "/qr?t=" + Date.now();
  img.alt = `QR code for ${name}`;
  const close = el("button", "btn sm", "Hide");
  close.type = "button";
  close.onclick = () => { box.hidden = true; box.replaceChildren(); };
  const pkg = el("a", "btn sm", "Package (.zip)");
  pkg.href = BASE + peerPath(name) + "/package";
  box.replaceChildren(el("h2", "", `${name}: scan in the WireGuard app`),
                      el("p", "meta", note || "Holds the device's private key: show it only to that device."),
                      img, el("div", "userrow-actions", ""));
  box.lastChild.append(pkg, close);
  box.hidden = false;
  box.scrollIntoView({ block: "nearest" });
}

async function act(p, what, to) {
  try {
    if (what === "remove") {
      const typed = prompt(`Revoke ${p.name}? The device loses VPN access at once. Type the name to confirm.`);
      if (typed === null) return;
      await api(`${peerPath(p.name)}?confirm=${encodeURIComponent(typed.trim())}`, { method: "DELETE" });
      $("vpnqrbox").hidden = true;
    } else if (what === "schedule") {
      await api(peerPath(p.name) + "/schedule", { method: "POST", body: JSON.stringify({ schedule: to }) });
    } else if (what === "group") {
      await api(peerPath(p.name) + "/group", { method: "POST", body: JSON.stringify({ group: to }) });
    } else if (what === "enabled") {
      const held = p.schedule ? ` Schedule ${p.schedule} takes over again at its next change.` : "";
      if (p.enabled && !confirm(`Turn off VPN access for ${p.name}? It disconnects at once; its setup stays and can be turned on again.${held}`)) return;
      await api(peerPath(p.name) + "/enabled", { method: "POST", body: JSON.stringify({ enabled: !p.enabled }) });
    } else if (what === "email") {
      const typed = prompt(`Owner's email for ${p.name} (empty = none):`, p.email || "");
      if (typed === null) return;
      await api(peerPath(p.name) + "/email", { method: "POST", body: JSON.stringify({ email: typed.trim() }) });
    } else if (what === "tags") {
      const typed = prompt(`Tags for ${p.name} (comma-separated, empty = none):`, p.tags.join(", "));
      if (typed === null) return;
      await api(peerPath(p.name) + "/tags", { method: "POST", body: JSON.stringify({ tags: tagList(typed) }) });
    } else {
      if (!confirm(`Switch ${p.name} to profile ${to}? The device must import the new config afterwards.`)) { loadPeers(); return; }
      await api(peerPath(p.name) + "/profile", { method: "POST", body: JSON.stringify({ profile: to }) });
      showQr(p.name, `Profile now ${to}: scan again or import the new package on the device.`);
    }
    loadPeers();
  } catch (x) { alert(x.message); loadPeers(); }
}

function profileForm(p) {
  const f = $("vpnpform");
  $("vpnpformh").textContent = p ? `Edit profile ${p.name}` : "Add a profile";
  $("vpnpname").value = p ? p.name : "";
  $("vpnpname").readOnly = !!p;
  $("vpnproutes").value = p ? p.routes.join("\n") : "";
  // New profile: a real value (owner 2026-10-27: a grey placeholder looked like a default but saved nothing)
  $("vpnpdns").value = p ? p.dns.join(", ") : PROFILES.length ? PROFILES[0].dns.join(", ") : "";
  $("vpnpdesc").value = p ? p.description : "";
  $("vpnpallow").value = p ? (p.allow || []).join("\n") : "";
  $("vpnpv6").checked = !!(p && p.ipv6);
  $("vpnptpl").hidden = !!p;
  $("vpnphint").hidden = !(p && p.peers);
  $("vpnphint").textContent = p && p.peers ? `${p.peers} device(s) use it: they must import their new config after saving.` : "";
  $("vpnpmsg").textContent = "";
  f.dataset.edit = p ? p.name : "";
  f.hidden = false;
  $("vpnpaddbtn").setAttribute("aria-expanded", "true");
  (p ? $("vpnproutes") : $("vpnpname")).focus();
}

// Profile templates (map vpn-standalone step 3): prefill the add form; DNS from the first existing profile.
const TEMPLATES = {
  lan: ["10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16", "LAN only: private networks through the VPN, the rest stays local."],
  full: ["0.0.0.0/0\n::/0", "Full tunnel: all traffic through the VPN."],
  hosts: ["", "Only the listed hosts through the VPN."],
  // map vpn-profile-rules (owner 2026-10-27): everything enters the tunnel, vpn1 passes only the allowed list
  locked: ["0.0.0.0/0\n::/0", "Full tunnel, listed hosts only: no internet while connected."],
};
function useTemplate(key) {
  const [routes, desc] = TEMPLATES[key];
  $("vpnproutes").value = routes;
  $("vpnproutes").placeholder = key === "hosts" ? "192.168.0.10/32" : "";
  $("vpnpdesc").value = desc;
  $("vpnpallow").value = "";
  if (!$("vpnpdns").value && PROFILES.length) $("vpnpdns").value = PROFILES[0].dns.join(", ");
  $("vpnpv6").checked = false;
  $(key === "hosts" ? "vpnproutes" : key === "locked" ? "vpnpallow" : "vpnpname").focus();
}

async function saveBulk(ev) {
  ev.preventDefault();
  $("vpnbmsg").textContent = "Creating…";
  try {
    const d = await api("api/peers/bulk", { method: "POST", body: JSON.stringify({ lines: $("vpnblines").value }) });
    $("vpnbmsg").textContent = `${d.created.length} created` + (d.error ? `; stopped at ${d.error}` : "");
    if (!d.error) $("vpnblines").value = "";
  } catch (x) { $("vpnbmsg").textContent = x.message; }
  loadPeers();
}

// List tables (owner 2026-10-27): a filter box filters as you type, PAGE rows per page with prev/next.
const PAGE = 15;
const PAGES = { devices: 0, profiles: 0, schedules: 0 };
// hit(item, term): optional extra match beyond the text, e.g. an IP inside a profile's routes
function matching(items, inputId, text, hit) {
  const terms = $(inputId).value.toLowerCase().split(/\s+/).filter(Boolean);
  return items.filter((it) => { const s = text(it).toLowerCase(); return terms.every((t) => s.includes(t) || (hit && hit(it, t))); });
}
// IPv4 "a.b.c.d" -> number, else null; inCidr also takes allow lines ("CIDR tcp 443": the port part is ignored)
function ip4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m || m.slice(1).some((o) => +o > 255)) return null;
  return m.slice(1).reduce((n, o) => n * 256 + +o, 0);
}
function inCidr(ip, cidr) {
  const [net, bits = "32"] = cidr.trim().split(/\s+/)[0].split("/");
  const base = ip4(net), size = 2 ** (32 - Number(bits));
  return base !== null && /^\d+$/.test(bits) && Number(bits) <= 32 && Math.floor(ip / size) === Math.floor(base / size);
}
// A profile reaches an address: inside its allow list (plus its DNS servers) when it has one, else inside its routes.
function reaches(p, term) {
  const ip = ip4(term);
  if (ip === null) return false;
  return ((p.allow || []).length ? [...p.allow, ...p.dns] : p.routes).some((c) => inCidr(ip, c));
}
// -> [rows of the current page, pager element (empty when one page is enough)]
function paged(key, items, rerender) {
  const pages = Math.max(1, Math.ceil(items.length / PAGE));
  PAGES[key] = Math.min(PAGES[key], pages - 1);
  const at = PAGES[key], nav = el("div", "userrow-actions vpnpager");
  if (pages > 1) {
    const go = (label, to) => {
      const b = el("button", "btn sm", label);
      b.type = "button";
      b.disabled = to < 0 || to >= pages;
      b.onclick = () => { PAGES[key] = to; rerender(); };
      return b;
    };
    nav.append(go("Previous", at - 1), el("span", "meta", `${at * PAGE + 1}–${Math.min((at + 1) * PAGE, items.length)} of ${items.length}`), go("Next", at + 1));
  }
  return [items.slice(at * PAGE, (at + 1) * PAGE), nav];
}

function renderProfiles() {
  const box = $("vpnpbox"), wrap = el("div", "tablewrap"), t = el("table");
  const found = matching(PROFILES, "vpnpq", (p) => [p.name, p.description, ...p.routes, ...p.dns, ...(p.allow || [])].join(" "), reaches);
  if (!found.length) { box.replaceChildren(el("div", "nodata", "No profile matches the filter.")); return; }
  const [rows, nav] = paged("profiles", found, renderProfiles);
  t.innerHTML = "<thead><tr><th>Profile</th><th>Routes</th><th class=\"kb-hide-sm\">DNS</th><th>Devices</th><th></th></tr></thead>";
  const tb = el("tbody");
  for (const p of rows) {
    const tr = el("tr"), who = el("td", "vpnwho"), acts = el("td"), row = el("div", "userrow-actions");
    who.append(el("strong", "", p.name), el("div", "meta", p.description));
    const routes = el("td", "mono", p.routes.join(", "));
    routes.append(el("div", "meta", p.ipv6 ? "IPv6 on" : "IPv6 off"));
    if ((p.allow || []).length) routes.append(el("div", "meta", "Allowed only: " + p.allow.join(", ")));
    tr.append(who, routes, el("td", "mono kb-hide-sm", p.dns.join(", ") || "device's own"),
              el("td", "num", String(p.peers)));
    const edit = el("button", "btn sm", "Edit"), del = el("button", "btn sm danger", "Delete");
    edit.type = del.type = "button";
    edit.onclick = () => profileForm(p);
    del.disabled = p.peers > 0 || PROFILES.length < 2;
    del.title = p.peers ? "In use: move its devices to another profile first" : "";
    del.onclick = async () => {
      const typed = prompt(`Delete profile ${p.name}? Type the name to confirm.`);
      if (typed === null) return;
      try { await api(`api/profiles/${encodeURIComponent(p.name)}?confirm=${encodeURIComponent(typed.trim())}`, { method: "DELETE" }); }
      catch (x) { alert(x.message); }
      loadPeers();
    };
    row.append(edit, del);
    acts.appendChild(row);
    tr.appendChild(acts);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  box.replaceChildren(wrap, nav);
}

// Schedules (api/schedules, map vpn-totp-schedules): table + form; times are vpn1's local wall clock.
const wall = (iso) => iso ? iso.replace("T", " ").slice(0, 16) : "";
// Editor rows (owner 2026-10-27: pickers, no free text): day ticks + from/to dropdowns; date pickers for dates.
const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const QUARTERS = Array.from({ length: 97 }, (_, i) => `${String(Math.floor(i / 4)).padStart(2, "0")}:${String(i % 4 * 15).padStart(2, "0")}`);
function timeSelect(label, value, last) {
  const s = el("select", "input vpntime");
  s.setAttribute("aria-label", label);
  const opts = last ? QUARTERS.slice(1) : QUARTERS.slice(0, -1);
  for (const t of opts.includes(value) ? opts : [...opts, value].sort()) { const o = el("option", "", t); o.value = t; s.appendChild(o); }
  s.value = value;
  return s;
}
function removeBtn(row, label) {
  const b = el("button", "btn sm ghost", "Remove");
  b.type = "button";
  b.setAttribute("aria-label", label);
  b.onclick = () => row.remove();
  return b;
}
function windowRow(w = { days: [0, 1, 2, 3, 4], start: "08:00", end: "17:00" }) {
  const row = el("div", "vpnwin"), days = el("div", "vpndays");
  DAYS.forEach((d, i) => {
    const lbl = el("label"), cb = el("input");
    cb.type = "checkbox";
    cb.value = d;
    cb.checked = w.days.includes(i);
    lbl.append(cb, " " + d[0].toUpperCase() + d.slice(1));
    days.appendChild(lbl);
  });
  row.append(days, timeSelect("From", w.start, false), el("span", "meta", "to"), timeSelect("To", w.end, true),
             removeBtn(row, "Remove these hours"));
  return row;
}
function dateRow(r = ["", ""]) {
  const row = el("div", "vpnwin"), a = el("input", "input"), b = el("input", "input");
  a.type = b.type = "date";
  a.required = true;
  a.value = r[0];
  b.value = r[1] !== r[0] ? r[1] : "";
  a.setAttribute("aria-label", "Date");
  b.setAttribute("aria-label", "To (optional)");
  row.append(a, el("span", "meta", "to"), b, removeBtn(row, "Remove this date"));
  return row;
}
// Rows -> the text the API parses ("mon,tue 08:00-17:00", "2026-12-24..2026-12-26").
function scheduleText() {
  const weekly = [], dates = [];
  for (const row of $("vpnscwins").children) {
    const days = [...row.querySelectorAll("input:checked")].map((c) => c.value);
    const [from, to] = row.querySelectorAll("select");
    if (!days.length) throw new Error("weekly hours: tick at least one day per row");
    weekly.push(`${days.join(",")} ${from.value}-${to.value}`);
  }
  for (const row of $("vpnscdlist").children) {
    const [a, b] = row.querySelectorAll("input");
    if (a.value) dates.push(b.value && b.value !== a.value ? `${a.value}..${b.value}` : a.value);
  }
  return { weekly: weekly.join("\n"), dates: dates.join("\n") };
}
function scheduleForm(s) {
  $("vpnscformh").textContent = s ? `Edit schedule ${s.name}` : "Add a schedule";
  $("vpnscname").value = s ? s.name : "";
  $("vpnscname").readOnly = !!s;
  for (const e of root.querySelectorAll(".vpnscnew")) e.hidden = !!s;
  $("vpnscdesc").value = s ? s.description : "";
  $("vpnscwins").replaceChildren(...(s ? s.windows || [] : [undefined]).map((w) => windowRow(w)));
  $("vpnscdlist").replaceChildren(...(s ? s.ranges || [] : []).map((r) => dateRow(r)));
  $("vpnscfrom").value = s ? s.starts : "";
  $("vpnscexp").value = s ? s.expires : "";
  $("vpnscmsg").textContent = "";
  $("vpnscform").dataset.edit = s ? s.name : "";
  $("vpnscform").hidden = false;
  $("vpnscadd").setAttribute("aria-expanded", "true");
  (s ? $("vpnscdesc") : $("vpnscname")).focus();
}
async function saveSchedule(ev) {
  ev.preventDefault();
  const edit = $("vpnscform").dataset.edit;
  $("vpnscmsg").textContent = "Saving…";
  try {
    const body = JSON.stringify({ name: $("vpnscname").value.trim(), description: $("vpnscdesc").value, ...scheduleText(),
                                  starts: $("vpnscfrom").value, expires: $("vpnscexp").value,
                                  group: edit ? "" : $("vpnscgroup").value });
    await api(edit ? `api/schedules/${encodeURIComponent(edit)}` : "api/schedules", { method: edit ? "PUT" : "POST", body });
    $("vpnscform").hidden = true;
    $("vpnscadd").setAttribute("aria-expanded", "false");
    loadPeers();
  } catch (x) { $("vpnscmsg").textContent = x.message; }
}
function renderSchedules() {
  const box = $("vpnscbox");
  $("vpnsctime").textContent = LAST ? `Server time: ${wall(LAST.now)} ${LAST.tz}` : "";
  if (!SCHEDULES.length) { box.replaceChildren(el("div", "nodata", "No schedules: devices are on or off by hand only.")); return; }
  const found = matching(SCHEDULES, "vpnscq", (s) => [s.name, s.description, s.weekly, s.dates, s.starts, s.expires].join(" "));
  if (!found.length) { box.replaceChildren(el("div", "nodata", "No schedule matches the filter.")); return; }
  const [rows, nav] = paged("schedules", found, renderSchedules);
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  t.innerHTML = "<thead><tr><th>Schedule</th><th>When</th><th>Now</th><th>Devices</th><th></th></tr></thead>";
  for (const s of rows) {
    const tr = el("tr"), who = el("td", "vpnwho"), when = el("td", "mono"), now = el("td"), acts = el("td"), row = el("div", "userrow-actions");
    who.append(el("strong", "", s.name), el("div", "meta", s.description));
    for (const line of [...s.weekly.split("\n"), ...s.dates.split("\n")].filter(Boolean)) when.appendChild(el("div", "", line));
    if (!s.weekly && !s.dates) when.appendChild(el("div", "", "whole valid period"));
    if (s.starts || s.expires) when.appendChild(el("div", "meta", [s.starts && `from ${s.starts}`, s.expires && `expires after ${s.expires}`].filter(Boolean).join(", ")));
    now.append(el("span", "pill " + (s.on ? "ok" : "nodot"), s.on ? "on" : "off"));
    if (s.next) now.append(el("div", "meta", `${s.on ? "off" : "on"} at ${wall(s.next)}`));
    const edit = el("button", "btn sm", "Edit"), del = el("button", "btn sm danger", "Delete");
    edit.type = del.type = "button";
    edit.onclick = () => scheduleForm(s);
    edit.disabled = !!s.locked;
    edit.title = s.locked || "";
    del.disabled = s.devices > 0 || !!s.locked || s.sign_in;
    del.title = s.locked || (s.devices ? "In use: set its devices to another schedule first" : s.sign_in ? "Sets an account's sign-in hours (Users)" : "");
    del.onclick = async () => {
      const typed = prompt(`Delete schedule ${s.name}? Type the name to confirm.`);
      if (typed === null) return;
      try { await api(`api/schedules/${encodeURIComponent(s.name)}?confirm=${encodeURIComponent(typed.trim())}`, { method: "DELETE" }); }
      catch (x) { alert(x.message); }
      loadPeers();
    };
    row.append(edit, del);
    acts.appendChild(row);
    tr.append(who, when, now, el("td", "num", String(s.devices)), acts);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  box.replaceChildren(wrap, nav);
}

// Last api/state answer: filter and page clicks re-render from it without a new request.
let LAST = null;
function fillSelect(sel, pairs) {
  const keep = sel.value;
  sel.replaceChildren(...pairs.map(([v, label]) => { const o = el("option", "", label); o.value = v; return o; }));
  if (pairs.some(([v]) => v === keep)) sel.value = keep;
}
async function loadPeers() {
  const box = $("vpnbox");
  let d;
  try { d = await api("api/state"); } catch (x) { box.replaceChildren(el("div", "nodata", x.message)); return; }
  LAST = d;
  PROFILES = d.profiles;
  SCHEDULES = d.schedules || [];
  ROLE = d.role || "admin";
  GROUPS = d.groups || [];
  applyRole();
  renderSchedules();
  fillAddForm();
  renderProfiles();
  renderPeers();
  if (isAdmin()) loadFirewall();  // after the state: names and profiles for the firewall table; also follows every change
}
function renderPeers() {
  const box = $("vpnbox"), d = LAST;
  $("vpndbar").replaceChildren();
  if (!d) return;
  if (!d.peers.length) { box.replaceChildren(el("div", "nodata", "No devices yet. Add one.")); return; }
  // Tag filter: same pills as the portal's Overview issue filter.
  const counts = {};
  for (const p of d.peers) for (const g of p.tags) counts[g] = (counts[g] || 0) + 1;
  const untagged = d.peers.filter((p) => !p.tags.length).length;
  if (tagFilter && !counts[tagFilter] && !(tagFilter === "-" && untagged)) tagFilter = "";
  const chips = el("div", "ovfilter");
  chips.style.marginBottom = "var(--s2)";
  const tagKeys = Object.keys(counts).sort();
  if (tagKeys.length) {
    for (const [tag, n, label] of [["", d.peers.length, "all"], ...tagKeys.map((g) => [g, counts[g], g]), ...(untagged ? [["-", untagged, "untagged"]] : [])]) {
      const b = el("button", "pill nodot" + (tagFilter === tag ? " on" : ""), `${label} ${n}`);
      b.type = "button";
      b.setAttribute("aria-pressed", String(tagFilter === tag));
      b.onclick = () => { tagFilter = tag; PAGES.devices = 0; renderPeers(); };
      chips.appendChild(b);
    }
  }
  const tagged = d.peers.filter((p) => !tagFilter || (tagFilter === "-" ? !p.tags.length : p.tags.includes(tagFilter)));
  const shown = matching(tagged, "vpndq", (p) => [p.name, p.address, p.email, p.profile, p.schedule, ...p.tags].join(" "));
  for (const n of [...PICKED]) if (!d.peers.some((p) => p.name === n)) PICKED.delete(n);
  const bar = $("vpndbar"), all = el("input"), mailBtn = el("button", "btn sm");
  all.type = "checkbox";
  all.setAttribute("aria-label", "Tick all matching devices");
  all.checked = shown.length > 0 && shown.every((p) => PICKED.has(p.name));
  all.onchange = () => { for (const p of shown) all.checked ? PICKED.add(p.name) : PICKED.delete(p.name); renderPeers(); };
  mailBtn.type = "button";
  mailBtn.textContent = `Email owners (${PICKED.size})`;
  mailBtn.disabled = !PICKED.size;
  mailBtn.onclick = () => notify([...PICKED]);
  const allLbl = el("label", "meta");
  allLbl.append(all, " all matching");
  bar.append(allLbl, mailBtn);
  if (!shown.length) { box.replaceChildren(chips, el("div", "nodata", "No device matches the filter.")); return; }
  const [rows, nav] = paged("devices", shown, renderPeers);
  const wrap = el("div", "tablewrap"), t = el("table");
  t.innerHTML = "<thead><tr><th aria-label=\"Tick\"></th><th>Device</th><th>Profile</th><th>Last handshake</th><th></th></tr></thead>";
  const tb = el("tbody"), now = Date.now() / 1000;
  for (const p of rows) {
    const tr = el("tr"), tick = el("td"), cb = el("input"), who = el("td"), prof = el("td"), seen = el("td");
    cb.type = "checkbox";
    cb.checked = PICKED.has(p.name);
    cb.setAttribute("aria-label", `Tick ${p.name}`);
    cb.onchange = () => { cb.checked ? PICKED.add(p.name) : PICKED.delete(p.name); mailBtn.textContent = `Email owners (${PICKED.size})`; mailBtn.disabled = !PICKED.size; };
    tick.appendChild(cb);
    tr.appendChild(tick);
    who.append(el("strong", "", p.name), el("div", "meta mono", p.address));
    if (p.email) who.appendChild(el("div", "meta", p.email));
    if (p.tags.length) {
      const tg = el("div");
      for (const g of p.tags) tg.appendChild(el("span", "pill nodot info", g));
      who.appendChild(tg);
    }
    const ps = el("select", "input vpnsel");
    ps.setAttribute("aria-label", `Profile of ${p.name}`);
    // a group admin picks only what an admin linked to the device's group
    const g = groupOf(p.group), mayP = (n) => isAdmin() || g.profiles.includes(n), mayS = (n) => isAdmin() || g.schedules.includes(n);
    for (const name of new Set([p.profile, ...PROFILES.map((x) => x.name).filter(mayP)])) { const o = el("option", "", name); o.value = name; ps.appendChild(o); }
    ps.value = p.profile;
    ps.title = profDesc(p.profile);
    ps.onchange = () => act(p, "profile", ps.value);
    prof.appendChild(ps);
    if (GROUPS.length > (isAdmin() ? 0 : 1)) {
      const gs = el("select", "input vpnsel vpnschedsel");
      gs.setAttribute("aria-label", `Group of ${p.name}`);
      for (const [v, label] of [...(isAdmin() ? [["", "no group"]] : []), ...GROUPS.map((x) => [x.name, "group: " + x.name])]) {
        const o = el("option", "", label); o.value = v; gs.appendChild(o);
      }
      gs.value = p.group || "";
      gs.onchange = () => act(p, "group", gs.value);
      prof.appendChild(gs);
    }
    if (SCHEDULES.length || p.schedule) {
      const ss = el("select", "input vpnsel vpnschedsel");
      ss.setAttribute("aria-label", `Schedule of ${p.name}`);
      for (const [v, label] of [["", "no schedule"], ...SCHEDULES.filter((s) => mayS(s.name) || s.name === p.schedule).map((s) => [s.name, "schedule: " + s.name])]) {
        const o = el("option", "", label); o.value = v; ss.appendChild(o);
      }
      ss.value = p.schedule || "";
      ss.onchange = () => act(p, "schedule", ss.value);
      prof.appendChild(ss);
    }
    const fresh = p.handshake && now - p.handshake < 180;  // WireGuard re-handshakes every 2 min while in use
    if (!p.enabled) seen.append(el("span", "pill warn", p.schedule && !p.hold ? "off by schedule" : "disabled"), " ");
    if (p.hold) {
      const h = el("span", "pill nodot", "manual hold");
      h.title = `Switched by hand: schedule ${p.schedule} takes over at its next change`;
      seen.append(h, " ");
    }
    seen.appendChild(el("span", "pill " + (fresh && p.enabled ? "ok" : "nodot"), p.handshake ? (fresh && p.enabled ? "connected" : ago(now - p.handshake) + " ago") : "never"));
    if (p.reimport) {
      const ri = el("span", "pill warn", "re-import");
      ri.title = "Its config changed: show the QR or download the package for the device";
      seen.append(" ", ri);
    }
    // traffic and created as meta lines, not columns: the table fits beside the info box (owner 2026-10-27)
    seen.appendChild(el("div", "meta", `in / out ${bytes(p.tx)} / ${bytes(p.rx)}`));
    who.appendChild(el("div", "meta", "added " + whenAt(p.created)));
    tr.append(who, prof, seen);
    const acts = el("td"), row = el("div", "userrow-actions");
    const btn = (label, fn, cls) => { const b = el("button", "btn sm" + (cls ? " " + cls : ""), label); b.type = "button"; b.onclick = fn; row.appendChild(b); };
    // slider: green on, grey off (owner 2026-10-27)
    const tg = el("button", "vpnswitch");
    tg.type = "button";
    tg.setAttribute("role", "switch");
    tg.setAttribute("aria-checked", String(p.enabled));
    tg.setAttribute("aria-label", `VPN access for ${p.name}`);
    tg.title = p.enabled ? "VPN access on: click to turn it off (setup kept)" : "VPN access off: click to turn it on";
    tg.onclick = () => act(p, "enabled");
    row.appendChild(tg);
    btn("QR", () => showQr(p.name));
    const conf = el("a", "btn sm", ".conf");
    conf.href = BASE + peerPath(p.name) + "/conf";
    row.appendChild(conf);
    btn("Tags", () => act(p, "tags"));
    btn("Owner", () => act(p, "email"));
    if (p.email) btn("Notify", () => notify([p.name]));
    btn("Revoke", () => act(p, "remove"), "danger");
    acts.appendChild(row);
    tr.appendChild(acts);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  box.replaceChildren(chips, wrap, nav);
}

// Notice mail (api/mail/notice): one mail per owner address, no keys; devices without an owner are skipped.
async function notify(names) {
  const kind = prompt(`Email the owners of ${names.join(", ")}.\nType "changed" (config changed: re-import) or "ready" (new device):`, "changed");
  if (kind === null) return;
  try {
    const d = await api("api/mail/notice", { method: "POST", body: JSON.stringify({ names, kind: kind.trim().toLowerCase() }) });
    alert(d.output);
    if (!d.failed.length) PICKED.clear();
  } catch (x) { alert(x.message); }
  loadPeers();
}

// Health map (api/health): devices, Internet, pfSense, vpn1, LAN/DNS, each once, with labelled links (renderHealth);
// the portal's Tools map nodes and popup.
const STATE = { ok: "ok", warn: "warn", bad: "crit", unknown: "unknown" };
const NODE_ICON = { pfsense: "shield", vpn1: "box", lan: "server", devices: "device" };
function closeInfo() {
  if (!info) return;
  info.anchor.setAttribute("aria-expanded", "false");
  info.box.remove();
  info = null;
}
function showInfo(n, anchor) {
  const same = info && info.anchor === anchor;
  closeInfo();
  if (same) return;
  const st = STATE[n.status] || "unknown";
  const box = el("div", "tinfo " + st);
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-label", `Details for ${n.label}`);
  box.onclick = (ev) => ev.stopPropagation();
  const h = el("h3"), x = el("button", "btn sm x", "Close");
  x.type = "button";
  x.onclick = closeInfo;
  h.append(el("span", "dot " + st), n.label, x);
  const dl = el("dl");
  dl.append(el("dt", "", "Status"), el("dd", "", `${n.status}: ${n.line}`));
  for (const [k, v] of Object.entries(n.details || {})) dl.append(el("dt", "", k), el("dd", "", String(v)));
  box.append(h, dl);
  $("vpnchain").appendChild(box);
  box.style.left = "0px";
  box.style.top = (anchor.offsetTop + anchor.offsetHeight + 8) + "px";
  anchor.setAttribute("aria-expanded", "true");
  info = { anchor, box };
  x.focus({ preventScroll: true });
}
function healthNode(n) {
  const st = STATE[n.status] || "unknown";
  const b = el("button", "tnode " + st);
  b.type = "button";
  b.setAttribute("aria-expanded", "false");
  b.setAttribute("aria-label", `${n.label}: ${n.status}, ${n.line}`);
  const head = el("div", "tn-head");
  head.append(el("span", "dot " + st), el("span", "tn-name", n.label), icon(NODE_ICON[n.id] || "device", "tn-kind"));
  b.append(head, el("div", "tn-sub", n.line));
  b.onclick = (ev) => { ev.stopPropagation(); showInfo(n, b); };
  return b;
}
function cloudNode(n) {
  const c = el("button", "cloud " + (STATE[n.status] || "unknown"));
  c.type = "button";
  c.style.font = "inherit";
  c.append(icon("cloud"), n.label);
  c.title = n.line;
  c.onclick = (ev) => { ev.stopPropagation(); showInfo(n, c); };
  return c;
}
// Each box once, top to bottom (grid row 2i+1; the gap above it row 2i). Links between neighbours: one wire and
// label each in the gap (arrow = who starts it). A link that skips boxes (pfSense -> LAN past vpn1) runs down a
// rail in column 2, its label in the gap above its lower end.
function renderHealth(d) {
  closeInfo();
  const pos = (id) => d.nodes.findIndex((n) => n.id === id);
  const links = d.links.map((l) => ({ ...l, a: Math.min(pos(l.from), pos(l.to)), z: Math.max(pos(l.from), pos(l.to)) }))
    .filter((l) => l.a >= 0);
  const rails = links.filter((l) => l.z - l.a > 1);
  const label = (l) => el("span", "vwlabel", (pos(l.from) < pos(l.to) ? "↓ " : "↑ ") + l.label);
  const parts = [];
  const put = (node, row) => { node.style.gridRow = String(row); parts.push(node); };
  d.nodes.forEach((n, i) => {
    if (i) {
      const here = links.filter((l) => l.a === i - 1 && l.z === i);
      const w = el("div", "vwire"), wires = el("div", "vwires"), labels = el("div", "vwlabels");
      wires.append(...here.map(() => el("div", "wire")));
      labels.append(...here.map(label), ...rails.filter((l) => l.z === i).map((l) => {
        const s = label(l);
        s.classList.add("vrlabel");  // right-aligned against the rail it belongs to
        return s;
      }));
      w.append(wires, labels);
      put(w, 2 * i);
    }
    put(n.id === "wan" ? cloudNode(n) : healthNode(n), 2 * i + 1);
  });
  for (const l of rails) {
    for (let row = 2 * l.a + 1; row <= 2 * l.z + 1; row++) {
      const r = el("div", "vrail " + (row === 2 * l.a + 1 ? "start" : row === 2 * l.z + 1 ? "end" : "mid"));
      put(r, row);
    }
  }
  $("vpnchain").classList.toggle("vrailed", rails.length > 0);
  $("vpnchain").replaceChildren(...parts);
  $("vpnhwhen").textContent = "Checked " + new Date(d.checked_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
async function loadHealth(run) {
  $("vpnhwhen").textContent = run ? "Running checks…" : "Checking…";
  $("vpnhrun").disabled = true;
  try { renderHealth(await api("api/health" + (run ? "/run" : ""), run ? { method: "POST" } : {})); }
  catch (x) { $("vpnchain").replaceChildren(el("div", "nodata", x.message)); $("vpnhwhen").textContent = ""; }
  finally { $("vpnhrun").disabled = false; }
}

// Server view (api/server): settings as label/value rows, the editable ones in a form; the ruleset on demand.
let SERVER = {};
function serverForm(open) {
  $("vpnsform").hidden = !open;
  $("vpnsedit").setAttribute("aria-expanded", String(open));
  if (!open) return;
  $("vpnsep").value = SERVER.endpoint && SERVER.endpoint.includes(":") ? SERVER.endpoint : "";
  $("vpnsport").value = SERVER.listen_port || 51820;
  $("vpnska").value = SERVER.keepalive || 25;
  $("vpnsmsg").textContent = "";
  $("vpnsep").focus();
}
async function saveServer(ev) {
  ev.preventDefault();
  const body = { endpoint: $("vpnsep").value.trim(), listen_port: Number($("vpnsport").value), keepalive: Number($("vpnska").value) };
  const changed = body.endpoint !== SERVER.endpoint || String(body.keepalive) !== SERVER.keepalive;
  if (changed && !confirm("Endpoint or keepalive changes rewrite every device's config: each device must import it again. Save?")) return;
  $("vpnsmsg").textContent = "Saving…";
  try {
    const d = await api("api/server", { method: "PUT", body: JSON.stringify(body) });
    serverForm(false);
    renderServer(d.settings);
    loadPeers();
  } catch (x) { $("vpnsmsg").textContent = x.message; }
}
// Reboot (map wg-admin-reboot): confirm names the host and who gets cut off; then wait until the server answers.
async function rebootServer() {
  const msg = $("vpnrebootmsg"), btn = $("vpnreboot");
  let d;
  try { d = await api("api/server/reboot"); } catch (x) { msg.textContent = x.message; return; }
  const who = d.connected.length ? `${d.connected.length} connected device(s) lose the VPN: ${d.connected.join(", ")}.` : "No devices are connected.";
  if (!confirm(`Reboot ${d.host}? ${who} The VPN and this page are back in about a minute.`)) return;
  btn.disabled = true;
  try { await api("api/server/reboot", { method: "POST", body: JSON.stringify({ host: d.host }) }); }
  catch (x) { msg.textContent = x.message; btn.disabled = false; return; }
  msg.textContent = `Rebooting ${d.host}…`;
  const start = Date.now();
  let down = false;
  const poll = async () => {
    let up = false;
    try { up = (await fetch(BASE + "api/me", { cache: "no-store" })).status < 500; } catch { /* still down */ }
    down = down || !up;
    // back: answered after it was seen down, or after 90 s (a reboot faster than one poll interval)
    if (up && (down || Date.now() - start > 90000)) { location.reload(); return; }
    if (Date.now() - start > 600000) { msg.textContent = `${d.host} has not answered for 10 minutes: check it in the hypervisor.`; btn.disabled = false; return; }
    setTimeout(poll, 5000);
  };
  setTimeout(poll, 8000);
}
async function loadServer() {
  const box = $("vpnsbox");
  let d;
  try { d = await api("api/server"); } catch (x) { box.replaceChildren(el("div", "nodata", x.message)); return; }
  renderServer(d.settings);
}
function renderServer(settings) {
  const box = $("vpnsbox");
  SERVER = Object.fromEntries(settings.map((s) => [s.key, s.value]));
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  for (const s of settings) {
    const tr = el("tr");
    tr.append(el("th", "", s.label), el("td", "mono vpnval", s.value));
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  box.replaceChildren(wrap);
}
// Network (api/network): current mode as rows; the form shows transit and gateway only where they apply.
let NET = {};
const NET_HINT = {
  nat: "Router: only the UDP port forward to the server.",
  route: "Router: a static route for 10.66.0.0/24 to the server (on the transit network if separate) and outbound NAT for it.",
};
function networkFields() {
  const route = $("vpnnmode").value === "route", split = route && $("vpnnout").value !== $("vpnnin").value;
  for (const e of root.querySelectorAll(".vpnnroute")) e.hidden = !route;
  for (const e of root.querySelectorAll(".vpnngw")) e.hidden = !split;
  $("vpnngw").required = split;
  $("vpnnhint").textContent = NET_HINT[$("vpnnmode").value] + " Applied at once; no device re-import.";
}
function networkForm(open) {
  $("vpnnform").hidden = !open;
  $("vpnnedit").setAttribute("aria-expanded", String(open));
  if (!open) return;
  for (const id of ["vpnnin", "vpnnout"]) {
    $(id).replaceChildren(...(NET.interfaces || []).map((i) => {
      const o = el("option", "", `${i.name} (${i.addr})`);
      o.value = i.name;
      return o;
    }));
  }
  $("vpnnmode").value = NET.mode || "nat";
  $("vpnnin").value = NET.lan_if || "";
  $("vpnnout").value = NET.transit_if || NET.lan_if || "";
  $("vpnngw").value = NET.transit_gw && NET.transit_gw !== "-" ? NET.transit_gw : "";
  $("vpnnmsg").textContent = "";
  networkFields();
  $("vpnnmode").focus();
}
async function saveNetwork(ev) {
  ev.preventDefault();
  const body = { mode: $("vpnnmode").value, in_if: $("vpnnin").value, out_if: $("vpnnout").value, gateway: $("vpnngw").value.trim() };
  if (!confirm("Device traffic switches at once; a wrong choice cuts the VPN until it is changed back here. Save?")) return;
  $("vpnnmsg").textContent = "Saving…";
  try {
    renderNetwork(await api("api/network", { method: "PUT", body: JSON.stringify(body) }));
    networkForm(false);
    loadHealth();
  } catch (x) { $("vpnnmsg").textContent = x.message; }
}
async function loadNetwork() {
  try { renderNetwork(await api("api/network")); }
  catch (x) { $("vpnnbox").replaceChildren(el("div", "nodata", x.message)); }
}
function renderNetwork(d) {
  NET = d;
  const addr = (n) => ((d.interfaces || []).find((i) => i.name === n) || {}).addr || "-";
  const split = d.mode === "route" && d.transit_if && d.transit_if !== d.lan_if;
  const rows = [["Mode", d.mode === "route" ? "Route (devices keep their 10.66.0.N)" : "NAT (devices appear as the server)"],
    ["Incoming VPN connections", `${d.lan_if} (${addr(d.lan_if)})`],
    ["Device traffic out", split ? `${d.transit_if} (${addr(d.transit_if)}) via ${d.transit_gw}` : `${d.lan_if}, same as incoming`]];
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  for (const [k, v] of rows) {
    const tr = el("tr");
    tr.append(el("th", "", k), el("td", "mono vpnval", v));
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  $("vpnnbox").replaceChildren(wrap);
}
function toggleRules() {
  const pre = $("vpnrulesbox"), open = pre.hidden;
  pre.hidden = !open;
  $("vpnrules").setAttribute("aria-expanded", String(open));
}

// Firewall summary: vpn-peer writes one block per profile p_<name> (dashes -> _): sets <id>_peers/_routes/_dns
// (+ 6 for IPv6), a DNS-only rule and accept rules "ip saddr @<id>_peers ip daddr X [tcp|udp dport P] accept".
function parseRuleset(text) {
  const sets = {}, accepts = {};
  let cur = null, buf = null;
  for (const line of text.split("\n")) {
    let m;
    // vpn-peer's file has a set on one line ("set X { type ...; elements = { a, b }; }"), `nft list` spreads it out
    if ((m = /^\s*set (\S+) \{/.exec(line))) { cur = m[1]; sets[cur] = []; }
    if (cur && buf === null && (m = /elements = \{(.*)/.exec(line))) buf = m[1];
    else if (cur && buf !== null) buf += " " + line;
    if (cur && buf !== null && buf.includes("}")) {
      sets[cur].push(...buf.split("}")[0].split(",").map((s) => s.trim()).filter(Boolean));
      buf = null;
      continue;
    }
    if (cur && buf === null && /^\s*\}\s*$/.test(line)) { cur = null; continue; }
    if ((m = /\b(ip6?) saddr @(\S+?)_peers6? (.*)\baccept\s*$/.exec(line)) && !line.includes("dport { 53, 853 }")) {
      const d = /daddr (\S+)(?: (tcp|udp) dport (\S+))?/.exec(m[3]);
      if (!d) continue;
      const dst = d[1].startsWith("@") ? sets[d[1].slice(1)] || [] : [d[1]];
      (accepts[m[2]] = accepts[m[2]] || []).push(...dst.map((x) => (m[1] === "ip6" ? "IPv6 " : "") + x + (d[2] ? ` ${d[2]} ${d[3]}` : "")));
    }
  }
  const ids = Object.keys(sets).filter((s) => /_peers$/.test(s)).map((s) => s.slice(0, -6));
  return ids.map((id) => ({ id, peers: [...sets[id + "_peers"], ...(sets[id + "_peers6"] || [])],
    dns: [...(sets[id + "_dns"] || []), ...(sets[id + "_dns6"] || [])], reach: accepts[id] || [], hasDns: (id + "_dns") in sets }));
}
const EVERY = /^(IPv6 )?(0\.0\.0\.0\/0|::\/0)$/;
function renderFirewall(text) {
  const box = $("vpnfwbox"), rows = parseRuleset(text);
  if (!rows.length) { box.replaceChildren(el("div", "nodata", "No profile rules found in the server's ruleset.")); return; }
  const byIp = {};
  for (const p of (LAST && LAST.peers) || []) for (const a of String(p.address).split(/[\s,]+/)) byIp[a.split("/")[0]] = p.name;
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  t.innerHTML = "<thead><tr><th>Connection profile</th><th>Devices let through now</th><th>May reach</th><th class=\"kb-hide-sm\">DNS</th><th></th></tr></thead>";
  for (const r of rows) {
    const prof = PROFILES.find((p) => "p_" + p.name.replace(/-/g, "_") === r.id);
    const tr = el("tr"), who = el("td", "vpnwho"), devs = el("td"), reach = el("td", "mono"), acts = el("td");
    who.append(el("strong", "", prof ? prof.name : r.id.slice(2)));
    if (prof && prof.description) who.append(el("div", "meta", prof.description));
    const ips = [...new Set(r.peers.map((a) => a.split("/")[0]))];
    if (!ips.length) devs.append(el("span", "meta", "none switched on"));
    for (const ip of ips) devs.append(el("div", "", byIp[ip] ? `${byIp[ip]} ` : ""), el("div", "meta mono", ip));
    const every = r.reach.filter((x) => EVERY.test(x));
    if (every.length) reach.append(el("div", "", "everything: LAN and internet" + (every.some((x) => x.startsWith("IPv6")) ? " (IPv4 + IPv6)" : "")));
    for (const x of r.reach.filter((y) => !EVERY.test(y))) reach.append(el("div", "", x));
    if (!r.reach.length) reach.append(el("span", "meta", "nothing"));
    tr.append(who, devs, reach, el("td", "mono kb-hide-sm", r.hasDns ? r.dns.join(", ") || "none" : "not restricted"));
    tr.append(acts);
    tb.append(tr);
    if (!prof) continue;
    const etr = el("tr"), etd = el("td");
    etr.hidden = true;
    etd.colSpan = 5;
    etr.append(etd);
    tb.append(etr);
    const b = el("button", "btn sm", "Edit rules"), s = el("button", "btn ghost sm", "Profile");
    b.type = s.type = "button";
    b.setAttribute("aria-expanded", "false");
    const show = (open) => {
      etr.hidden = !open;
      b.setAttribute("aria-expanded", String(open));
      if (open) etd.replaceChildren(ruleEditor(prof, () => show(false)));
    };
    b.onclick = () => show(etr.hidden);
    s.title = "Routes, DNS and IPv6 of the profile";
    s.onclick = () => { showView("profiles"); profileForm(prof); };
    acts.append(el("div", "userrow-actions"));
    acts.firstChild.append(b, s);
  }
  t.append(tb);
  wrap.append(t);
  const always = el("ul", "meta vpnfwalways");
  for (const s of ["Replies to a device's own connections pass.", "The server itself answers ping only; devices never reach each other.",
                   "DNS (ports 53, 853) only to the servers in the DNS column.", "Anything not listed above is dropped.",
                   /nfproto ipv6 masquerade/.test(text)  // vpn.env NAT4=off: IPv4 routed, IPv6 still NAT66
                     ? "IPv4 is routed: logs show each device's own tunnel address. IPv6 leaves with the server's address (NAT)."
                     : "Traffic leaves the server with the server's LAN address (NAT)."]) always.append(el("li", "", s));
  box.replaceChildren(wrap, el("p", "meta", "For every device:"), always);
}
// Rule editor (owner 2026-10-27: edit the firewall on the Server view): one row per allowed destination, saved as
// the profile's allow list through api/profiles; vpn-peer checks it and reloads the firewall, no re-import.
function ruleRow(line) {
  const [dst = "", proto = "", port = ""] = (line || "").split(/\s+/);
  const row = el("div", "vpnfwrule"), d = el("input", "input mono"), p = el("select", "input"), n = el("input", "input mono");
  d.value = /^[\d.]+\/32$|:.*\/128$/.test(dst) ? dst.split("/")[0] : dst;  // one host: shown as a plain address
  d.placeholder = "192.168.0.10 or 192.168.4.0/24";
  d.setAttribute("aria-label", "Destination address or network");
  for (const [v, t] of [["", "all ports"], ["tcp", "TCP port"], ["udp", "UDP port"]]) { const o = el("option", "", t); o.value = v; p.append(o); }
  p.value = proto;
  p.setAttribute("aria-label", "Protocol");
  n.value = port;
  n.placeholder = "443 or 8000-8100";
  n.setAttribute("aria-label", "Port or port range");
  n.hidden = !proto;
  p.onchange = () => { n.hidden = !p.value; if (p.value) n.focus(); };
  for (const x of [d, n]) { x.autocomplete = "off"; x.spellcheck = false; x.setAttribute("autocapitalize", "none"); }
  const rm = el("button", "btn ghost sm", "Remove");
  rm.type = "button";
  rm.onclick = () => row.remove();
  row.append(d, p, n, rm);
  return row;
}
function ruleLine(row) {
  const [d, p, n] = row.querySelectorAll("input, select");
  let dst = d.value.trim();
  if (!dst) return "";
  if (!dst.includes("/")) dst += dst.includes(":") ? "/128" : "/32";
  return p.value ? `${dst} ${p.value} ${n.value.trim()}` : dst;
}
function ruleEditor(prof, close) {
  const box = el("div", "vpnfwedit"), list = el("div", "vpnfwrules"), msg = el("span", "meta"), bar = el("div", "userrow-actions");
  msg.setAttribute("role", "status");
  for (const line of prof.allow || []) list.append(ruleRow(line));
  const add = el("button", "btn sm", "Add rule"), save = el("button", "btn primary sm", "Save"), cancel = el("button", "btn ghost sm", "Cancel");
  add.type = save.type = cancel.type = "button";
  add.onclick = () => { const r = ruleRow(""); list.append(r); r.querySelector("input").focus(); };
  cancel.onclick = close;
  save.onclick = async () => {
    const allow = [...list.children].map(ruleLine).filter(Boolean).join("\n");
    msg.textContent = "Saving…";
    save.disabled = true;
    try {
      await api(`api/profiles/${encodeURIComponent(prof.name)}`, { method: "PUT", body: JSON.stringify({ name: prof.name,
        routes: prof.routes.join("\n"), dns: prof.dns.join(", "), description: prof.description, ipv6: prof.ipv6, allow }) });
      loadPeers();  // re-reads the profiles and the live ruleset: the table shows what the server now enforces
    } catch (x) { msg.textContent = x.message; save.disabled = false; }
  };
  bar.append(add, save, cancel, msg);
  box.append(el("p", "meta", `Allowed destinations for ${prof.name}. No rules: its devices reach everything in its routes ` +
    `(${prof.routes.join(", ")}). With rules: only these, plus its DNS servers; the rest is dropped. Up to 20.`), list, bar);
  if (!(prof.allow || []).length) add.onclick();
  return box;
}
async function loadFirewall() {
  try {
    const text = (await api("api/server/ruleset")).text;
    $("vpnrulesbox").textContent = text;
    renderFirewall(text);
  } catch (x) { $("vpnfwbox").replaceChildren(el("div", "nodata", x.message)); }
}

// Mail settings (api/mail): the password is write-only; the view shows only whether one is stored.
let MAIL = {};
function renderMail(m) {
  MAIL = m;
  const rows = [["From", m.from_addr || "not set"], ["Relay", m.host ? `${m.host}:${m.port}` : "not set"],
                ["Security", m.security], ["User", m.user || "none"], ["Password", m.password_set ? "stored" : "none"]];
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  for (const [k, v] of rows) { const tr = el("tr"); tr.append(el("th", "", k), el("td", "mono vpnval", v)); tb.appendChild(tr); }
  t.appendChild(tb);
  wrap.appendChild(t);
  $("vpnmbox").replaceChildren(wrap);
  $("vpnmtest").disabled = !m.ready;
}
async function loadMail() {
  try { renderMail(await api("api/mail")); } catch (x) { $("vpnmbox").replaceChildren(el("div", "nodata", x.message)); }
}
function mailForm(open) {
  $("vpnmform").hidden = !open;
  $("vpnmedit").setAttribute("aria-expanded", String(open));
  if (!open) return;
  $("vpnmfrom").value = MAIL.from_addr || "";
  $("vpnmhost").value = MAIL.host || "";
  $("vpnmport").value = MAIL.port || 25;
  $("vpnmsec").value = MAIL.security || "none";
  $("vpnmuser").value = MAIL.user || "";
  $("vpnmpw").value = "";
  $("vpnmpwclear").checked = false;
  $("vpnmmsg").textContent = "";
  $("vpnmfrom").focus();
}
async function saveMail(ev) {
  ev.preventDefault();
  const pw = $("vpnmpw").value;
  const body = { from_addr: $("vpnmfrom").value.trim(), host: $("vpnmhost").value.trim(), port: Number($("vpnmport").value),
                 security: $("vpnmsec").value, user: $("vpnmuser").value.trim(),
                 password: $("vpnmpwclear").checked ? "" : pw ? pw : null };
  $("vpnmmsg").textContent = "Saving…";
  try { renderMail(await api("api/mail", { method: "PUT", body: JSON.stringify(body) })); mailForm(false); }
  catch (x) { $("vpnmmsg").textContent = x.message; }
}
async function testMail() {
  const to = prompt("Send a test mail to:", MAIL.from_addr || "");
  if (to === null) return;
  $("vpnmtmsg").textContent = "Sending…";
  try { $("vpnmtmsg").textContent = (await api("api/mail/test", { method: "POST", body: JSON.stringify({ to: to.trim() }) })).output; }
  catch (x) { $("vpnmtmsg").textContent = x.message; }
}

function showView(name) {
  for (const b of root.querySelectorAll("[data-vview]")) b.setAttribute("aria-pressed", String(b.dataset.vview === name));
  for (const v of root.querySelectorAll(".vpnview")) v.hidden = v.id !== "vpnv" + name;
}

// Roles (map wg-admin-groups): the state says who is asking; admin-only parts are hidden for group admins (the
// server refuses them anyway) and their lists are not loaded.
let ROLE = "admin", GROUPS = [];
const isAdmin = () => ROLE === "admin";
const groupOf = (name) => GROUPS.find((g) => g.name === name) || { profiles: [], schedules: [] };
function applyRole() {
  for (const e of root.querySelectorAll(".vpnadmin")) e.style.display = isAdmin() ? "" : "none";
  const cur = root.querySelector("[data-vview][aria-pressed=true]");
  if (!isAdmin() && cur && cur.classList.contains("vpnadmin")) showView("devices");
}
// Device add form: group first; a group admin's profile and schedule lists follow the group's links.
function fillAddForm() {
  fillSelect($("vpngroup"), [...(isAdmin() ? [["", "no group"]] : []), ...GROUPS.map((g) => [g.name, g.name])]);
  const g = groupOf($("vpngroup").value);
  fillSelect($("vpnprof"), PROFILES.filter((p) => isAdmin() || g.profiles.includes(p.name)).map((p) => [p.name, p.name]));
  fillSelect($("vpnaddsched"), [["", "no schedule"], ...SCHEDULES.filter((s) => isAdmin() || g.schedules.includes(s.name)).map((s) => [s.name, s.name])]);
  fillSelect($("vpnscgroup"), [...(isAdmin() ? [["", "no group (admins only)"]] : []), ...GROUPS.map((x) => [x.name, x.name])]);
  $("vpnprofhint").textContent = profDesc($("vpnprof").value);
}
const ticks = (box, names, picked) => box.replaceChildren(...names.map((n) => {
  const lbl = el("label"), cb = el("input");
  cb.type = "checkbox";
  cb.value = n;
  cb.checked = picked.includes(n);
  lbl.append(cb, " " + n);
  return lbl;
}));
const ticked = (box) => [...box.querySelectorAll("input:checked")].map((c) => c.value);
async function del(path, what, name, after) {
  const typed = prompt(`Delete ${what} ${name}? Type the name to confirm.`);
  if (typed === null) return;
  try { await api(`${path}/${encodeURIComponent(name)}?confirm=${encodeURIComponent(typed.trim())}`, { method: "DELETE" }); }
  catch (x) { alert(x.message); }
  after();
}

// Groups tab (api/groups)
let GROUPLIST = [];
async function loadGroups() {
  try { GROUPLIST = (await api("api/groups")).groups; renderGroups(); }
  catch (x) { $("vpngbox").replaceChildren(el("div", "nodata", x.message)); }
}
function renderGroups() {
  if (!GROUPLIST.length) { $("vpngbox").replaceChildren(el("div", "nodata", "No groups: every device is managed by admins only.")); return; }
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  t.innerHTML = "<thead><tr><th>Group</th><th>Profiles</th><th>Schedules</th><th>Devices</th><th>Group admins</th><th></th></tr></thead>";
  for (const g of GROUPLIST) {
    const tr = el("tr"), who = el("td", "vpnwho"), acts = el("td"), row = el("div", "userrow-actions");
    who.append(el("strong", "", g.name), el("div", "meta", g.description));
    const edit = el("button", "btn sm", "Edit"), rm = el("button", "btn sm danger", "Delete");
    edit.type = rm.type = "button";
    edit.onclick = () => groupForm(g);
    rm.disabled = g.devices > 0 || g.admins.length > 0;
    rm.title = rm.disabled ? "In use: move its devices and group admins first" : "";
    rm.onclick = () => del("api/groups", "group", g.name, () => { loadGroups(); loadPeers(); });
    row.append(edit, rm);
    acts.appendChild(row);
    tr.append(who, el("td", "mono", g.profiles.join(", ") || "-"), el("td", "mono", g.schedules.join(", ") || "-"),
              el("td", "num", String(g.devices)), el("td", "", g.admins.join(", ") || "-"), acts);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  $("vpngbox").replaceChildren(wrap);
}
function groupForm(g) {
  $("vpngformh").textContent = g ? `Edit group ${g.name}` : "Add a group";
  $("vpngname").value = g ? g.name : "";
  $("vpngname").readOnly = !!g;
  $("vpngdesc").value = g ? g.description : "";
  ticks($("vpngprofs"), PROFILES.map((p) => p.name), g ? g.profiles : []);
  ticks($("vpngscheds"), SCHEDULES.map((s) => s.name), g ? g.schedules : []);
  $("vpngmsg").textContent = "";
  $("vpngform").dataset.edit = g ? g.name : "";
  $("vpngform").hidden = false;
  $("vpngname").focus();
}
async function saveGroup(ev) {
  ev.preventDefault();
  const edit = $("vpngform").dataset.edit;
  const body = JSON.stringify({ name: $("vpngname").value.trim(), description: $("vpngdesc").value,
                                profiles: ticked($("vpngprofs")), schedules: ticked($("vpngscheds")) });
  try {
    await api(edit ? `api/groups/${encodeURIComponent(edit)}` : "api/groups", { method: edit ? "PUT" : "POST", body });
    $("vpngform").hidden = true;
    loadGroups();
    loadPeers();
  } catch (x) { $("vpngmsg").textContent = x.message; }
}

// Users tab (api/users): accounts, roles, sign-in hours, expiry; the authenticator policy per role
let USERS = [];
async function loadUsers() {
  try { renderUsers(await api("api/users")); } catch (x) { $("vpnubox").replaceChildren(el("div", "nodata", x.message)); }
}
function renderUsers(d) {
  USERS = d.users;
  $("vpnpoladmin").checked = d.totp_roles.includes("admin");
  $("vpnpolgroup").checked = d.totp_roles.includes("group-admin");
  const wrap = el("div", "tablewrap"), t = el("table"), tb = el("tbody");
  t.innerHTML = "<thead><tr><th>User</th><th>Role</th><th>Sign-in</th><th>State</th><th></th></tr></thead>";
  for (const u of USERS) {
    const tr = el("tr"), who = el("td", "vpnwho"), acts = el("td"), row = el("div", "userrow-actions");
    who.append(el("strong", "", u.name));
    if (u.default) who.append(" ", el("span", "pill nodot info", "default admin"));
    if (u.you) who.append(" ", el("span", "pill nodot", "you"));
    const role = el("td", "", u.role === "admin" ? "admin" : "group admin");
    if (u.groups.length) role.appendChild(el("div", "meta", u.groups.join(", ")));
    const when = el("td", "", u.schedule || "any time");
    if (u.expires) when.appendChild(el("div", "meta", `expires after ${u.expires}`));
    const state = el("td");
    state.append(el("span", "pill " + (u.state === "active" ? "ok" : "warn"), u.state), " ",
                 el("span", "pill nodot", u.totp ? "2-step on" : "2-step off"));
    const btn = (label, fn, cls, off) => { const b = el("button", "btn sm" + (cls ? " " + cls : ""), label); b.type = "button"; b.onclick = fn; b.disabled = !!off; row.appendChild(b); };
    btn("Edit", () => userForm(u));
    btn("Password", () => userPassword(u));
    btn("Reset 2-step", () => userAction(u, "totp-reset", `Remove ${u.name}'s authenticator? They sign in with the password and set it up again.`), "", !u.totp);
    btn("Delete", () => del("api/users", "user", u.name, loadUsers), "danger", u.default || u.you);
    acts.appendChild(row);
    tr.append(who, role, when, state, acts);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  $("vpnubox").replaceChildren(wrap);
}
async function userForm(u) {
  // groups fetched each time: GROUPS is from the page load and missed groups made since (owner 2026-10-29)
  let groups = GROUPS.map((g) => g.name);
  try { groups = (await api("api/groups")).groups.map((g) => g.name); } catch { /* keep the page-load list */ }
  $("vpnuformh").textContent = u ? `Edit ${u.name}` : "Add a user";
  $("vpnuname").value = u ? u.name : "";
  $("vpnuname").readOnly = !!u;
  $("vpnupw").value = "";
  $("vpnupw").hidden = $("vpnupwl").hidden = !!u;
  $("vpnupw").required = !u;
  $("vpnurole").value = u ? u.role : "group-admin";
  ticks($("vpnugroups"), groups, u ? u.groups : []);
  $("vpnunogroups").hidden = groups.length > 0;
  fillSelect($("vpnusched"), [["", "any time"], ...SCHEDULES.map((s) => [s.name, s.name])]);
  $("vpnusched").value = u ? u.schedule : "";
  $("vpnuexp").value = u ? u.expires : "";
  $("vpnudis").checked = !!(u && u.disabled);
  // the default admin keeps its role and state: only password and authenticator change (server checks too)
  for (const id of ["vpnurole", "vpnusched", "vpnuexp", "vpnudis"]) $(id).disabled = !!(u && u.default);
  $("vpnugfs").hidden = $("vpnurole").value !== "group-admin";
  $("vpnumsg").textContent = u && u.default ? "Default admin: only its password and authenticator can change." : "";
  $("vpnuform").dataset.edit = u ? u.name : "";
  $("vpnuform").hidden = false;
  (u ? $("vpnurole") : $("vpnuname")).focus();
}
async function saveUser(ev) {
  ev.preventDefault();
  const edit = $("vpnuform").dataset.edit;
  const body = { role: $("vpnurole").value, groups: ticked($("vpnugroups")), schedule: $("vpnusched").value,
                 expires: $("vpnuexp").value, disabled: $("vpnudis").checked };
  if (!edit) Object.assign(body, { name: $("vpnuname").value.trim(), password: $("vpnupw").value });
  try {
    renderUsers(await api(edit ? `api/users/${encodeURIComponent(edit)}` : "api/users", { method: edit ? "PUT" : "POST", body: JSON.stringify(body) }));
    $("vpnuform").hidden = true;
    loadGroups();
  } catch (x) { $("vpnumsg").textContent = x.message; }
}
async function userPassword(u) {
  const pw = prompt(`New password for ${u.name} (at least 12 characters). Their sessions end.`);
  if (!pw) return;
  try { alert((await api(`api/users/${encodeURIComponent(u.name)}/password`, { method: "POST", body: JSON.stringify({ password: pw }) })).output); }
  catch (x) { alert(x.message); }
}
async function userAction(u, verb, question) {
  if (!confirm(question)) return;
  try { renderUsers(await api(`api/users/${encodeURIComponent(u.name)}/${verb}`, { method: "POST" })); }
  catch (x) { alert(x.message); }
}
async function savePolicy() {
  const roles = [...($("vpnpoladmin").checked ? ["admin"] : []), ...($("vpnpolgroup").checked ? ["group-admin"] : [])];
  try {
    const d = await api("api/policy", { method: "PUT", body: JSON.stringify({ totp_roles: roles }) });
    $("vpnpolmsg").textContent = d.output;
    renderUsers(d);
  } catch (x) { $("vpnpolmsg").textContent = x.message; }
}

export function reload() {
  loadPeers().then(() => { if (isAdmin()) { loadHealth(); loadServer(); loadNetwork(); loadMail(); loadGroups(); loadUsers(); } });
}

// opts.onAuth: called when the API says "sign in required" (standalone page: show the login; portal: reload).
export function mount(target, opts = {}) {
  root = target;
  if (opts.onAuth) onAuth = opts.onAuth;
  root.innerHTML = MARKUP;
  document.addEventListener("click", (ev) => { if (info && !info.box.contains(ev.target)) closeInfo(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeInfo(); });
  $("vpnreload").onclick = reload;
  $("vpnhrun").onclick = () => loadHealth(true);
  $("vpnrules").onclick = toggleRules;
  $("vpnfwreload").onclick = loadFirewall;
  $("vpnsedit").onclick = () => serverForm($("vpnsform").hidden);
  $("vpnscancel").onclick = () => serverForm(false);
  $("vpnreboot").onclick = rebootServer;
  $("vpnsform").onsubmit = saveServer;
  $("vpnnedit").onclick = () => networkForm($("vpnnform").hidden);
  $("vpnncancel").onclick = () => networkForm(false);
  $("vpnnform").onsubmit = saveNetwork;
  $("vpnnmode").onchange = $("vpnnin").onchange = $("vpnnout").onchange = networkFields;
  $("vpnmedit").onclick = () => mailForm($("vpnmform").hidden);
  $("vpnmcancel").onclick = () => mailForm(false);
  $("vpnmform").onsubmit = saveMail;
  $("vpnmtest").onclick = testMail;
  for (const b of $("vpnptpl").querySelectorAll("button")) b.onclick = () => useTemplate(b.dataset.tpl);
  const bulk = (open) => { $("vpnbform").hidden = !open; $("vpnbulkbtn").setAttribute("aria-expanded", String(open)); };
  $("vpnbulkbtn").onclick = () => { showView("devices"); bulk($("vpnbform").hidden); $("vpnbmsg").textContent = ""; $("vpnblines").focus(); };
  $("vpnbcancel").onclick = () => bulk(false);
  $("vpnbform").onsubmit = saveBulk;
  $("vpnprof").onchange = () => { $("vpnprofhint").textContent = profDesc($("vpnprof").value); };
  $("vpnpaddbtn").onclick = () => profileForm(null);
  $("vpngroup").onchange = fillAddForm;
  $("vpngadd").onclick = () => groupForm(null);
  $("vpngcancel").onclick = () => { $("vpngform").hidden = true; };
  $("vpngform").onsubmit = saveGroup;
  $("vpnuadd").onclick = () => userForm(null);
  $("vpnucancel").onclick = () => { $("vpnuform").hidden = true; };
  $("vpnuform").onsubmit = saveUser;
  $("vpnurole").onchange = () => { $("vpnugfs").hidden = $("vpnurole").value !== "group-admin"; };
  $("vpnpolsave").onclick = savePolicy;
  $("vpnscadd").onclick = () => scheduleForm(null);
  $("vpnscwinadd").onclick = () => $("vpnscwins").appendChild(windowRow());
  $("vpnscdadd").onclick = () => $("vpnscdlist").appendChild(dateRow());
  // Tabs: Profiles | Schedules | Devices | Server settings, each list with its own filter box (owner 2026-10-27)
  for (const b of root.querySelectorAll("[data-vview]")) b.onclick = () => showView(b.dataset.vview);
  for (const [id, key, fn] of [["vpndq", "devices", renderPeers], ["vpnpq", "profiles", renderProfiles], ["vpnscq", "schedules", renderSchedules]])
    $(id).oninput = () => { PAGES[key] = 0; fn(); };
  $("vpnsccancel").onclick = () => { $("vpnscform").hidden = true; $("vpnscadd").setAttribute("aria-expanded", "false"); };
  $("vpnscform").onsubmit = saveSchedule;
  $("vpnpcancel").onclick = () => { $("vpnpform").hidden = true; $("vpnpaddbtn").setAttribute("aria-expanded", "false"); };
  $("vpnpform").onsubmit = async (e) => {
    e.preventDefault();
    const edit = $("vpnpform").dataset.edit, name = $("vpnpname").value.trim();
    const body = JSON.stringify({ name, routes: $("vpnproutes").value, dns: $("vpnpdns").value, description: $("vpnpdesc").value, ipv6: $("vpnpv6").checked, allow: $("vpnpallow").value });
    try {
      const r = await api(edit ? `api/profiles/${encodeURIComponent(edit)}` : "api/profiles", { method: edit ? "PUT" : "POST", body });
      $("vpnpform").hidden = true;
      $("vpnpaddbtn").setAttribute("aria-expanded", "false");
      if (edit && r.profile && r.profile.peers) alert(`${r.output}. Those devices must scan the new QR or import the new config.`);
      loadPeers();
    } catch (x) { $("vpnpmsg").textContent = x.message; }
  };
  $("vpnaddbtn").onclick = () => { showView("devices"); $("vpnform").hidden = false; $("vpnaddbtn").setAttribute("aria-expanded", "true"); $("vpnmsg").textContent = ""; $("vpnname").focus(); };
  $("vpncancel").onclick = () => { $("vpnform").hidden = true; $("vpnaddbtn").setAttribute("aria-expanded", "false"); };
  $("vpnform").onsubmit = async (e) => {
    e.preventDefault();
    const name = $("vpnname").value.trim();
    try {
      await api("api/peers", { method: "POST", body: JSON.stringify({ name, profile: $("vpnprof").value, group: $("vpngroup").value, tags: tagList($("vpntags").value), email: $("vpnemail").value.trim() }) });
      const sched = $("vpnaddsched").value;
      if (sched) await api(peerPath(name) + "/schedule", { method: "POST", body: JSON.stringify({ schedule: sched }) });
      $("vpnform").hidden = true;
      $("vpnaddbtn").setAttribute("aria-expanded", "false");
      $("vpnname").value = "";
      $("vpntags").value = "";
      $("vpnemail").value = "";
      showQr(name);
      loadPeers();
    } catch (x) { $("vpnmsg").textContent = x.message; }
  };
  reload();
}
