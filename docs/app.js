/* safe-url-guard web version  SPDX-License-Identifier: GPL-3.0-or-later */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var T = I18N.t;
  function L() { return I18N.lang; }
  I18N.apply();
  document.querySelectorAll("[data-lang]").forEach(function (b) {
    b.addEventListener("click", function () { I18N.set(b.dataset.lang); rerun(); });
  });
  /* re-render the current result in the new language */
  var lastRun = null;
  function rerun() { if (lastRun) lastRun(); }
  var builtin = {};
  fetch("builtin_blocklist.txt").then(function (r) { return r.text(); }).then(function (t) {
    t.split(/\r?\n/).forEach(function (l) { l = l.split("#")[0].trim().toLowerCase(); if (l) builtin[l] = true; });
  }).catch(function () {});
  function inBuiltin(host) {
    var parts = host.split(".");
    for (var i = 0; i < parts.length - 1; i++) if (builtin[parts.slice(i).join(".")]) return parts.slice(i).join(".");
    return null;
  }
  var rulesPromise = fetch("scam_rules.json").then(function (r) { return r.json(); }).then(ScamCore.compile);

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---------- tabs ---------- */
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () { showTab(b.dataset.tab); });
  });
  function showTab(name) {
    document.querySelectorAll(".tabs button").forEach(function (b) {
      b.setAttribute("aria-selected", String(b.dataset.tab === name));
    });
    ["msg", "url", "qr"].forEach(function (t) { $("tab-" + t).hidden = t !== name; });
  }

  /* ---------- link check ---------- */
  function urlBlock(raw, withRdap) {
    var h = ScamCore.urlHeuristics(raw, T);
    var hit = h.host ? inBuiltin(h.host) : null;
    if (hit) h.warnings.unshift(T("builtin_hit", { d: hit }));
    var lv = hit ? 3 : h.warnings.length ? 2 : 0;
    var id = "rdap-" + Math.random().toString(36).slice(2);
    var html = '<div class="verdict lv' + lv + '">' + T(lv === 3 ? "url_danger" : lv ? "url_warn" : "url_ok") + "</div>" +
      "<p><code>" + esc(raw) + "</code></p><ul>" +
      h.warnings.map(function (w) { return "<li>" + esc(w) + "</li>"; }).join("") +
      (withRdap && h.host ? '<li id="' + id + '">' + T("rdap_loading") + "</li>" : "") + "</ul>" +
      '<p class="hint">' + T("no_blocklist") + "</p>";
    if (withRdap && h.host) setTimeout(function () { domainAge(h.host, id); }, 0);
    return html;
  }

  var bootstrapPromise = null;
  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/rdap+json, application/json" } }).then(function (r) {
      if (!r.ok) { var e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
      return r.json();
    });
  }
  function domainAge(host, id) {
    var el = $(id);
    var lookup = T("lookup");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { el.innerHTML = T("rdap_ip"); return; }
    bootstrapPromise = bootstrapPromise || getJSON("https://data.iana.org/rdap/dns.json");
    bootstrapPromise.then(function (bs) {
      var base = ScamCore.rdapBase(host, bs);
      if (!base) { el.innerHTML = T("rdap_no_tld") + lookup; return; }
      if (base.slice(-1) !== "/") base += "/";
      var cands = ScamCore.candidates(host);
      (function next(i) {
        if (i >= cands.length) { el.innerHTML = T("rdap_not_found") + lookup; return; }
        getJSON(base + "domain/" + cands[i]).then(function (data) {
          var d = ScamCore.registrationDate(data);
          if (!d) { el.innerHTML = T("rdap_no_date") + lookup; return; }
          var days = Math.floor((Date.now() - d.getTime()) / 86400000);
          var v = ScamCore.verdictForDays(days);
          var msg = T("rdap_reg", { d: esc(cands[i]), date: d.toISOString().slice(0, 10), days: days });
          if (v === "DANGER") msg = "<b>⚠ " + msg + T("rdap_danger") + "</b>";
          else if (v === "WARN") msg = "<b>⚠ " + msg + T("rdap_warn") + "</b>";
          else msg += T("rdap_old");
          el.innerHTML = msg;
        }).catch(function (e) {
          if (e.status === 404) next(i + 1);
          else el.innerHTML = T("rdap_fail", { e: esc(e.message) }) + lookup;
        });
      })(0);
    }).catch(function (e) {
      bootstrapPromise = null;
      el.innerHTML = T("rdap_fail", { e: esc(e.message) }) + lookup;
    });
  }

  $("url-btn").addEventListener("click", function run() {
    var v = $("url-input").value.trim();
    $("url-result").innerHTML = v ? urlBlock(v, $("url-rdap").checked) : "";
    lastRun = run;
  });
  $("url-input").addEventListener("keydown", function (e) { if (e.key === "Enter") $("url-btn").click(); });

  /* ---------- message check ---------- */
  $("msg-btn").addEventListener("click", function run() {
    lastRun = run;
    var text = $("msg-input").value;
    if (!text.trim()) { $("msg-result").innerHTML = ""; return; }
    rulesPromise.then(function (rules) {
      var r = ScamCore.analyze(text, rules);
      var html = '<div class="verdict lv' + r.level + '">' + T("level")[r.level] + "</div>";
      if (r.hits.length) {
        html += "<h2>" + T("found") + "</h2><ul>" + r.hits.map(function (h) {
          return '<li><span class="tag">' + esc(ScamCore.pick(rules.categories[h.category], L())) + "</span>" + esc(ScamCore.pick(h.reason, L())) +
            '<br><span class="match">' + T("matched") + " " + h.matches.slice(0, 5).map(function (m) { return "<mark>" + esc(m) + "</mark>"; }).join(" ") + "</span></li>";
        }).join("") + "</ul>";
      }
      if (r.combos.length) {
        html += "<h2>" + T("combos") + "</h2><ul>" + r.combos.map(function (c) { return "<li>▲ " + esc(ScamCore.pick(c.reason, L())) + "</li>"; }).join("") + "</ul>";
      }
      if (r.urls.length) {
        html += "<h2>" + T("urls_in_msg") + "</h2>" + r.urls.map(function (u) { return urlBlock(u, false); }).join("") +
          '<p class="hint">' + T("url_age_hint") + "</p>";
      }
      if (r.level >= 2) {
        html += "<h2>" + T("advice") + "</h2><ul>" + ScamCore.pick(rules.advice, L()).map(function (a) { return "<li>" + esc(a) + "</li>"; }).join("") + "</ul>";
      } else if (r.level <= 1) {
        html += '<p class="hint">' + T("low_hint") + "</p>";
      }
      $("msg-result").innerHTML = html;
    }).catch(function (e) {
      $("msg-result").innerHTML = T("rules_failed") + esc(e.message);
    });
  });

  /* ---------- QR-code check ---------- */
  function scanImage(file) {
    if (!file || !/^image\//.test(file.type)) return;
    var out = $("qr-result");
    out.innerHTML = T("qr_reading");
    lastRun = function () { scanImage(file); };
    var img = new Image();
    var url = URL.createObjectURL(file);
    img.onload = function () {
      var scale = Math.min(1, 1600 / Math.max(img.width, img.height));
      var c = document.createElement("canvas");
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      var ctx = c.getContext("2d");
      ctx.drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url);
      var data = ctx.getImageData(0, 0, c.width, c.height);
      var code = jsQR(data.data, c.width, c.height, { inversionAttempts: "attemptBoth" });
      if (!code || !code.data) { out.innerHTML = T("qr_none"); return; }
      var t = code.data;
      if (/^(https?:\/\/|www\.)/i.test(t)) {
        out.innerHTML = "<h2>" + T("qr_url_h") + "</h2>" + urlBlock(t, true) +
          '<p class="hint">' + T("qr_url_hint") + "</p>";
      } else {
        out.innerHTML = "<h2>" + T("qr_text_h") + "</h2><p><code>" + esc(t) + "</code></p>";
        rulesPromise.then(function (rules) {
          var r = ScamCore.analyze(t, rules);
          if (r.level) out.innerHTML += '<div class="verdict lv' + r.level + '">' + T("level")[r.level] + "</div>";
        });
      }
    };
    img.onerror = function () { out.innerHTML = T("qr_bad_img"); URL.revokeObjectURL(url); };
    img.src = url;
  }
  $("qr-input").addEventListener("change", function (e) { scanImage(e.target.files[0]); });
  document.addEventListener("paste", function (e) {
    var items = (e.clipboardData || {}).items || [];
    for (var i = 0; i < items.length; i++) {
      if (items[i].type.indexOf("image/") === 0) {
        showTab("qr");
        scanImage(items[i].getAsFile());
        e.preventDefault();
        return;
      }
    }
  });
})();
