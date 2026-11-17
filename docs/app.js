/* safe-url-guard 网页版  SPDX-License-Identifier: GPL-3.0-or-later */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var LEVEL = ["未发现明显的诈骗特征", "风险：低", "风险：中，请小心", "风险：高，很可能是诈骗"];
  var rulesPromise = fetch("scam_rules.json").then(function (r) { return r.json(); }).then(ScamCore.compile);

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---------- 标签页 ---------- */
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () { showTab(b.dataset.tab); });
  });
  function showTab(name) {
    document.querySelectorAll(".tabs button").forEach(function (b) {
      b.setAttribute("aria-selected", String(b.dataset.tab === name));
    });
    ["msg", "url", "qr"].forEach(function (t) { $("tab-" + t).hidden = t !== name; });
  }

  /* ---------- 网址检查 ---------- */
  function urlBlock(raw, withRdap) {
    var h = ScamCore.urlHeuristics(raw);
    var lv = h.warnings.length ? 2 : 0;
    var id = "rdap-" + Math.random().toString(36).slice(2);
    var html = '<div class="verdict lv' + lv + '">' + (lv ? "有可疑特征" : "没有发现明显的可疑特征") + "</div>" +
      "<p><code>" + esc(raw) + "</code></p><ul>" +
      h.warnings.map(function (w) { return "<li>" + esc(w) + "</li>"; }).join("") +
      (withRdap && h.host ? '<li id="' + id + '">正在查询域名注册时间……</li>' : "") + "</ul>" +
      '<p class="hint">网页版无法比对恶意网站黑名单。需要比对的话，请用 Python 版的 <code>safe_url_guard.py</code>，或使用浏览器自带的安全浏览保护。</p>';
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
    var lookup = ' 可以在 <a href="https://lookup.icann.org/" target="_blank" rel="noopener">ICANN Lookup</a> 手动查询。';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { el.innerHTML = "这是 IP 地址，无法查询注册时间。"; return; }
    bootstrapPromise = bootstrapPromise || getJSON("https://data.iana.org/rdap/dns.json");
    bootstrapPromise.then(function (bs) {
      var base = ScamCore.rdapBase(host, bs);
      if (!base) { el.innerHTML = "IANA 的 RDAP 列表中没有这个域名后缀，无法自动查询。" + lookup; return; }
      if (base.slice(-1) !== "/") base += "/";
      var cands = ScamCore.candidates(host);
      (function next(i) {
        if (i >= cands.length) { el.innerHTML = "RDAP 中找不到这个域名。" + lookup; return; }
        getJSON(base + "domain/" + cands[i]).then(function (data) {
          var d = ScamCore.registrationDate(data);
          if (!d) { el.innerHTML = "RDAP 数据中没有注册日期。" + lookup; return; }
          var days = Math.floor((Date.now() - d.getTime()) / 86400000);
          var v = ScamCore.verdictForDays(days);
          var msg = esc(cands[i]) + " 注册于 " + d.toISOString().slice(0, 10) + "（" + days + " 天前）";
          if (v === "DANGER") msg = "<b>⚠ " + msg + "：注册不到 1 个月，非常可疑</b>";
          else if (v === "WARN") msg = "<b>⚠ " + msg + "：注册不到半年，请小心</b>";
          else msg += "（老域名也不代表一定安全）";
          el.innerHTML = msg;
        }).catch(function (e) {
          if (e.status === 404) next(i + 1);
          else el.innerHTML = "无法查询注册时间（" + esc(e.message) + "）。" + lookup;
        });
      })(0);
    }).catch(function (e) {
      bootstrapPromise = null;
      el.innerHTML = "无法查询注册时间（" + esc(e.message) + "）。" + lookup;
    });
  }

  $("url-btn").addEventListener("click", function () {
    var v = $("url-input").value.trim();
    $("url-result").innerHTML = v ? urlBlock(v, $("url-rdap").checked) : "";
  });
  $("url-input").addEventListener("keydown", function (e) { if (e.key === "Enter") $("url-btn").click(); });

  /* ---------- 消息检查 ---------- */
  $("msg-btn").addEventListener("click", function () {
    var text = $("msg-input").value;
    if (!text.trim()) { $("msg-result").innerHTML = ""; return; }
    rulesPromise.then(function (rules) {
      var r = ScamCore.analyze(text, rules);
      var html = '<div class="verdict lv' + r.level + '">' + LEVEL[r.level] + "</div>";
      if (r.hits.length) {
        html += "<h2>发现的特征</h2><ul>" + r.hits.map(function (h) {
          return '<li><span class="tag">' + esc(rules.categories[h.category]) + "</span>" + esc(h.reason) +
            '<br><span class="match">命中：' + h.matches.slice(0, 5).map(function (m) { return "<mark>" + esc(m) + "</mark>"; }).join(" ") + "</span></li>";
        }).join("") + "</ul>";
      }
      if (r.combos.length) {
        html += "<h2>危险的组合</h2><ul>" + r.combos.map(function (c) { return "<li>▲ " + esc(c.reason) + "</li>"; }).join("") + "</ul>";
      }
      if (r.urls.length) {
        html += "<h2>消息中的网址</h2>" + r.urls.map(function (u) { return urlBlock(u, false); }).join("") +
          '<p class="hint">想查网址的注册时间，可以复制到“网址检查”里查。</p>';
      }
      if (r.level >= 2) {
        html += "<h2>建议</h2><ul>" + rules.advice.map(function (a) { return "<li>" + esc(a) + "</li>"; }).join("") + "</ul>";
      } else if (r.level <= 1) {
        html += '<p class="hint">没有发现常见话术，不代表一定安全。只要对方要钱、要验证码，或者叫你“别告诉别人”，请先找人商量。</p>';
      }
      $("msg-result").innerHTML = html;
    }).catch(function (e) {
      $("msg-result").innerHTML = "规则文件加载失败：" + esc(e.message);
    });
  });

  /* ---------- 二维码检查 ---------- */
  function scanImage(file) {
    if (!file || !/^image\//.test(file.type)) return;
    var out = $("qr-result");
    out.innerHTML = "正在识别……";
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
      if (!code || !code.data) { out.innerHTML = "没有识别到二维码。请换一张更清晰的图片，或只截取二维码部分。"; return; }
      var t = code.data;
      if (/^(https?:\/\/|www\.)/i.test(t)) {
        out.innerHTML = "<h2>二维码里的网址</h2>" + urlBlock(t, true) +
          '<p class="hint">确认没问题后再打开。不要在扫码打开的页面里输入密码或银行卡信息。</p>';
      } else {
        out.innerHTML = "<h2>二维码内容（不是网址）</h2><p><code>" + esc(t) + "</code></p>";
        rulesPromise.then(function (rules) {
          var r = ScamCore.analyze(t, rules);
          if (r.level) out.innerHTML += '<div class="verdict lv' + r.level + '">' + LEVEL[r.level] + "</div>";
        });
      }
    };
    img.onerror = function () { out.innerHTML = "无法读取这张图片。"; URL.revokeObjectURL(url); };
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
