/*
 * scam_core.js - 诈骗消息 / 网址检查的核心逻辑（浏览器和 Node.js 通用）。
 * 规则来自 scam_rules.json，和 Python 版 scam_check.py 共用。
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

  /* 网址的可疑特征（与 safe_url_guard.py 的 heuristics 对应） */
  function urlHeuristics(raw) {
    var warn = [];
    var u;
    try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw); }
    catch (e) { return { host: "", warnings: ["无法解析这个网址"] }; }
    var host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (u.protocol === "http:") warn.push("未使用 HTTPS（通信未加密）");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(":") >= 0) warn.push("直接使用 IP 地址而不是域名");
    if (host.indexOf("xn--") >= 0) warn.push("域名含有特殊字符（punycode / xn--），可能是用相似字符仿冒的网站");
    if (u.username || u.password) warn.push("网址中含有 '@'，真实目标可能与看起来的不同");
    if ((host.match(/\./g) || []).length >= 4) warn.push("子域名层级过多");
    if (raw.length > 200) warn.push("网址异常地长");
    if (u.port && u.port !== "80" && u.port !== "443") warn.push("使用非标准端口 " + u.port);
    return { host: host.replace(/^www\./, ""), warnings: warn };
  }

  /* ---------- RDAP（域名注册时间） ---------- */
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

  return {
    compile: compile, analyze: analyze, urlHeuristics: urlHeuristics,
    rdapBase: rdapBase, candidates: candidates, registrationDate: registrationDate,
    verdictForDays: verdictForDays
  };
});
