/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;
const $ = id => document.getElementById(id);

I18N.init().then(lang => {
  document.title = I18N.t("opt_title");
  $("lang").value = lang;
});

api.storage.local.get(["allowlist", "denylist"]).then(st => {
  $("allowlist").value = st.allowlist || "";
  $("denylist").value = st.denylist || "";
});

$("lang").addEventListener("change", async () => {
  await api.storage.local.set({ lang: $("lang").value });
  location.reload();
});

$("save").addEventListener("click", async () => {
  await api.storage.local.set({ allowlist: $("allowlist").value, denylist: $("denylist").value });
  api.runtime.sendMessage({ type: "applyRules" }, res => {
    $("msg").textContent = res && !res.error
      ? I18N.t("opt_saved", { n: res.count.toLocaleString() })
      : I18N.t("opt_save_fail", { e: res && res.error });
  });
});
