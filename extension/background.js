/*
 * safe-url-guard browser extension - background
 * Runs when the browser starts, updates the blocklists every 24 hours and blocks
 * listed sites with declarativeNetRequest.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
"use strict";

const api = typeof browser !== "undefined" ? browser : chrome;

const FEEDS = {
  // URLhaus (abuse.ch) was removed in Nov 2026: its public downloads now return HTTP 410 Gone.
  openphish: { url: "https://openphish.com/feed.txt", kind: "urls" }
};
const UPDATE_MINUTES = 24 * 60;
const CHUNK = 1000;          // domains per rule
const ALLOW_RULE_ID = 1;
const FIRST_BLOCK_ID = 100;

/* ---------- blocklist parsing ---------- */
function normalizeHost(h) {
  h = String(h || "").trim().toLowerCase().replace(/\.$/, "");
  return h.startsWith("www.") ? h.slice(4) : h;
}
function hostOf(u) {
  try { return normalizeHost(new URL(/^[a-z]+:\/\//i.test(u) ? u : "http://" + u).hostname); }
  catch (e) { return ""; }
}
function validDomain(h) {
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h) && h.length <= 253;
}
function parseFeed(text, kind) {
  const out = new Set();
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;
    const h = kind === "hosts" ? normalizeHost(line.split(/\s+/)[1]) : hostOf(line);
    if (h && h !== "localhost" && validDomain(h)) out.add(h);
  }
  return out;
}
function parseList(text) {
  const out = new Set();
  for (let line of String(text || "").split(/\r?\n/)) {
    line = line.split("#")[0].trim();
    if (!line) continue;
    const h = line.includes("/") ? hostOf(line) : normalizeHost(line);
    if (validDomain(h)) out.add(h);
  }
  return out;
}

/* ---------- built-in list (confirmed scam sites shipped with the extension) ---------- */
async function loadBuiltin() {
  try {
    const resp = await fetch(api.runtime.getURL("builtin_blocklist.txt"));
    return parseList(await resp.text());
  } catch (e) {
    return new Set();
  }
}

/* ---------- rules ---------- */
async function applyRules() {
  const st = await api.storage.local.get(["feeds", "allowlist", "denylist"]);
  const feeds = st.feeds || {};
  const allow = parseList(st.allowlist);
  const block = new Set(parseList(st.denylist));
  for (const h of await loadBuiltin()) block.add(h);
  // only sources that are still configured (drops data from removed feeds)
  for (const name of Object.keys(FEEDS)) for (const h of (feeds[name] || {}).hosts || []) block.add(h);
  for (const h of allow) block.delete(h);

  const domains = [...block].sort();
  const blockedUrl = api.runtime.getURL("blocked.html");
  const rules = [];
  for (let i = 0; i < domains.length; i += CHUNK) {
    rules.push({
      id: FIRST_BLOCK_ID + i / CHUNK,
      priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: blockedUrl + "#\\0" } },
      condition: {
        regexFilter: "^.*$",
        requestDomains: domains.slice(i, i + CHUNK),
        resourceTypes: ["main_frame", "sub_frame"]
      }
    });
  }
  if (allow.size) {
    rules.push({
      id: ALLOW_RULE_ID, priority: 2, action: { type: "allow" },
      condition: { requestDomains: [...allow], resourceTypes: ["main_frame", "sub_frame"] }
    });
  }
  const old = await api.declarativeNetRequest.getDynamicRules();
  await api.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: old.map(r => r.id), addRules: rules
  });
  await api.storage.local.set({ blockedCount: domains.length });
  return domains.length;
}

/* ---------- updates ---------- */
let updating = null;
function updateFeeds() {
  if (updating) return updating;
  updating = (async () => {
    const st = await api.storage.local.get(["feeds"]);
    const feeds = st.feeds || {};
    const errors = {};
    for (const [name, f] of Object.entries(FEEDS)) {
      try {
        const resp = await fetch(f.url, { cache: "no-store" });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const hosts = parseFeed(await resp.text(), f.kind);
        if (hosts.size === 0) throw new Error("empty list");
        feeds[name] = { hosts: [...hosts], updated: Date.now() };
      } catch (e) {
        errors[name] = String(e.message || e);   // keep the previous list on failure
      }
    }
    await api.storage.local.set({ feeds, lastAttempt: Date.now(), errors });
    const count = await applyRules();
    return { count, errors };
  })().finally(() => { updating = null; });
  return updating;
}

async function ensureFresh() {
  api.alarms.create("update", { periodInMinutes: UPDATE_MINUTES });
  const { lastAttempt } = await api.storage.local.get("lastAttempt");
  if (!lastAttempt || Date.now() - lastAttempt > UPDATE_MINUTES * 60 * 1000) {
    await updateFeeds();
  }
}

api.runtime.onInstalled.addListener(() => { ensureFresh(); });
api.runtime.onStartup.addListener(() => { ensureFresh(); });
api.alarms.onAlarm.addListener(a => { if (a.name === "update") updateFeeds(); });

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "updateNow") return updateFeeds();
    if (msg.type === "applyRules") return { count: await applyRules() };
    if (msg.type === "status") {
      const st = await api.storage.local.get(["feeds", "blockedCount", "lastAttempt", "errors"]);
      const feeds = {};
      for (const [name, f] of Object.entries(FEEDS)) {
        const d = (st.feeds || {})[name];
        feeds[name] = { count: d ? d.hosts.length : 0, updated: d ? d.updated : null,
          error: (st.errors || {})[name] || null };
      }
      return { blockedCount: st.blockedCount || 0, lastAttempt: st.lastAttempt || null, feeds };
    }
    return null;
  })().then(sendResponse, e => sendResponse({ error: String(e) }));
  return true;
});
