/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;
const $ = id => document.getElementById(id);

api.storage.local.get(["allowlist", "denylist"]).then(st => {
  $("allowlist").value = st.allowlist || "";
  $("denylist").value = st.denylist || "";
});

$("save").addEventListener("click", async () => {
  await api.storage.local.set({ allowlist: $("allowlist").value, denylist: $("denylist").value });
  api.runtime.sendMessage({ type: "applyRules" }, res => {
    $("msg").textContent = res && !res.error
      ? `已保存（正在拦截 ${res.count.toLocaleString()} 个网站）`
      : "保存失败：" + (res && res.error);
  });
});
