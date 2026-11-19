/*
 * scam_core.js - core logic for checking scam messages and URLs (works in browsers and Node.js).
 * Rules come from scam_rules.json, shared with the Python version (scam_check.py).
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.ScamCore = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var URL_RE = /(?:https?:\/\/|www\.)[^\s<>"'，。、）)」】]+/gi;

  function compile(rules) {
    rules.rules.forEach(function (r) { r._re = new RegExp(r.pattern, "gi"); });
    return rules;
  }

  function analyze(text, rules) {
    var hits = [];
    rules.rules.forEach(function (r) {
      var found = {};
      r._re.lastIndex = 0;
      var m;
      while ((m = r._re.exec(text)) !== null) {
        if (m[0] === "") { r._re.lastIndex++; continue; }
        found[m[0]] = true;
      }
      var list = Object.keys(found).sort();
      if (list.length) hits.push({ id: r.id, category: r.category, weight: r.weight, reason: r.reason, matches: list });
    });
    // most serious first; keep rule order for equal weights
    hits = hits.map(function (h, i) { return [h, i]; })
      .sort(function (a, b) { return b[0].weight - a[0].weight || a[1] - b[1]; })
      .map(function (x) { return x[0]; });
    var cats = {};
    hits.forEach(function (h) { cats[h.category] = true; });
    var combos = rules.combos.filter(function (c) {
      return c.categories.every(function (x) { return cats[x]; });
    });
    var score = hits.reduce(function (s, h) { return s + h.weight; }, 0) +
      combos.reduce(function (s, c) { return s + c.bonus; }, 0);
    var t = rules.thresholds;
    var level = score >= t.high ? 3 : score >= t.medium ? 2 : score > 0 ? 1 : 0;
    var urls = (text.match(URL_RE) || []).map(function (u) { return u.replace(/[.,!?;:]+$/, ""); });
    return { score: score, level: level, hits: hits, combos: combos, urls: urls };
  }

  /* Suspicious URL traits (mirrors heuristics() in safe_url_guard.py).
     Returns message keys; `tr(key, vars)` turns them into text (defaults to the key). */
  function urlHeuristics(raw, tr) {
    tr = tr || function (k) { return k; };
    var warn = [];
    var u;
    try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw); }
    catch (e) { return { host: "", warnings: [tr("h_bad")] }; }
    var host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (u.protocol === "http:") warn.push(tr("h_http"));
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(":") >= 0) warn.push(tr("h_ip"));
    if (host.indexOf("xn--") >= 0) warn.push(tr("h_idn"));
    if (u.username || u.password) warn.push(tr("h_at"));
    if ((host.match(/\./g) || []).length >= 4) warn.push(tr("h_sub"));
    if (raw.length > 200) warn.push(tr("h_long"));
    if (u.port && u.port !== "80" && u.port !== "443") warn.push(tr("h_port", { port: u.port }));
    return { host: host.replace(/^www\./, ""), warnings: warn };
  }

  /* ---------- RDAP (domain registration date) ---------- */
  function rdapBase(domain, bootstrap) {
    var best = null, bestLen = -1;
    (bootstrap.services || []).forEach(function (svc) {
      svc[0].forEach(function (tld) {
        if ((domain === tld || domain.slice(-tld.length - 1) === "." + tld) && tld.length > bestLen) {
          var https = svc[1].filter(function (x) { return x.indexOf("https://") === 0; });
          best = (https.length ? https : svc[1])[0];
          bestLen = tld.length;
        }
      });
    });
    return best;
  }

  function candidates(host) {
    var parts = host.split("."), out = [];
    for (var n = 2; n <= parts.length; n++) out.push(parts.slice(-n).join("."));
    return out;
  }

  function registrationDate(rdap) {
    var evs = rdap.events || [];
    for (var i = 0; i < evs.length; i++) {
      if (evs[i].eventAction === "registration" && evs[i].eventDate) {
        var d = new Date(evs[i].eventDate);
        return isNaN(d) ? null : d;
      }
    }
    return null;
  }

  function verdictForDays(days) {
    return days < 30 ? "DANGER" : days < 180 ? "WARN" : "OK";
  }

  /* pick the right language from {"en": ..., "zh": ...} */
  function pick(v, lang) {
    return v && typeof v === "object" && "en" in v ? (v[lang] || v.en) : v;
  }

  return {
    pick: pick, compile: compile, analyze: analyze, urlHeuristics: urlHeuristics,
    rdapBase: rdapBase, candidates: candidates, registrationDate: registrationDate,
    verdictForDays: verdictForDays
  };
});
