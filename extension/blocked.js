/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
(function () {
  var target = decodeURIComponent(location.hash.slice(1) || "");
  if (target) {
    var el = document.getElementById("url");
    // 只显示文字，不生成链接，防止误点
    el.textContent = target.replace(/^https?:\/\//i, "").replace(/\./g, "[.]");
    el.hidden = false;
  }
  document.getElementById("back").addEventListener("click", function () {
    if (history.length > 1) history.back();
    else location.replace("about:blank");
  });
})();
