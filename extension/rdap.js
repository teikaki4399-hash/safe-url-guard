/*
 * rdap.js - look up when a domain was registered, via RDAP (RFC 9082/9083).
 * The RDAP server for each domain ending comes from IANA's bootstrap file (RFC 9224).
 * Same logic as domain_age.py and docs/scam_core.js. Works in the extension's service
 * worker (importScripts) and in Node.js (tests).
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Rdap = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
  const NEW_DAYS = 30;               // "registered less than 30 days ago" -> warning bar

  /* server for the longest matching domain ending; prefers https */
  function rdapBase(domain, bootstrap) {
    let best = null, bestLen = -1;
    for (const svc of (bootstrap && bootstrap.services) || []) {
      for (const tld of svc[0]) {
        if ((domain === tld || domain.endsWith("." + tld)) && tld.length > bestLen) {
          const https = svc[1].filter(u => u.startsWith("https://"));
          best = (https.length ? https : svc[1])[0];
          bestLen = tld.length;
        }
      }
    }
    return best;
  }

  /* a.b.example.co.jp -> co.jp, example.co.jp, b.example.co.jp, ... (shortest first) */
  function candidates(host) {
    const parts = host.split("."), out = [];
    for (let n = 2; n <= parts.length; n++) out.push(parts.slice(-n).join("."));
    return out;
  }

  function registrationDate(rdap) {
    for (const ev of (rdap && rdap.events) || []) {
      if (ev.eventAction === "registration" && ev.eventDate) {
        const d = new Date(ev.eventDate);
        return isNaN(d) ? null : d;
      }
    }
    return null;
  }

  /* hosts that never get a lookup: IP addresses, single labels, local names */
  function lookupable(host) {
    if (!host || host.indexOf(".") < 0) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(":") >= 0) return false;
    return !/\.(local|localhost|internal|test|example|invalid|lan|home\.arpa)$/.test(host);
  }

  /*
   * Look up a host. getJSON(url) must resolve to parsed JSON or reject with an Error
   * whose .status is the HTTP status. Resolves to {domain, registered: Date} or
   * {domain, registered: null, reason}.
   */
  async function lookup(host, bootstrap, getJSON) {
    const base0 = rdapBase(host, bootstrap);
    if (!base0) return { domain: host, registered: null, reason: "no_rdap" };
    const base = base0.endsWith("/") ? base0 : base0 + "/";
    for (const dom of candidates(host)) {
      let data;
      try {
        data = await getJSON(base + "domain/" + dom);
      } catch (e) {
        if (e && e.status === 404) continue;      // e.g. "co.jp" is not a registered domain
        return { domain: host, registered: null, reason: "error" };
      }
      return { domain: dom, registered: registrationDate(data), reason: null };
    }
    return { domain: host, registered: null, reason: "not_found" };
  }

  function ageDays(registered, now) {
    return Math.floor(((now || Date.now()) - registered.getTime()) / 86400000);
  }

  return { BOOTSTRAP_URL, NEW_DAYS, rdapBase, candidates, registrationDate, lookupable, lookup, ageDays };
});
