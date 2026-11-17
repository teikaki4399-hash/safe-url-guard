/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
(function () {
  I18N.init().then(function () { document.title = I18N.t("blocked_title"); });
  var target = decodeURIComponent(location.hash.slice(1) || "");
  if (target) {
    var el = document.getElementById("url");
    // plain text only (no link) so it cannot be clicked by mistake
    el.textContent = target.replace(/^https?:\/\//i, "").replace(/\./g, "[.]");
    el.hidden = false;
  }
  document.getElementById("back").addEventListener("click", function () {
    if (history.length > 1) history.back();
    else location.replace("about:blank");
  });
})();
