/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;
const $ = id => document.getElementById(id);
const fmt = t => t ? new Date(t).toLocaleString() : "尚未更新";

function send(msg) {
  return new Promise(resolve => api.runtime.sendMessage(msg, resolve));
}

async function refresh() {
  const s = await send({ type: "status" });
  if (!s || s.error) { $("last").textContent = "读取状态失败"; return; }
  $("count").textContent = s.blockedCount.toLocaleString();
  $("feeds").innerHTML = "";
  for (const f of Object.values(s.feeds)) {
    const li = document.createElement("li");
    li.textContent = `${f.label}：${f.count.toLocaleString()} 个（${fmt(f.updated)}）`;
    if (f.error) {
      const e = document.createElement("div");
      e.className = "err";
      e.textContent = "上次更新失败：" + f.error;
      li.appendChild(e);
    }
    $("feeds").appendChild(li);
  }
  $("last").textContent = "上次检查更新：" + fmt(s.lastAttempt) + "（每 24 小时自动更新）";
}

$("update").addEventListener("click", async () => {
  $("update").disabled = true;
  $("update").textContent = "更新中…";
  await send({ type: "updateNow" });
  $("update").disabled = false;
  $("update").textContent = "立即更新";
  refresh();
});
$("options").addEventListener("click", () => api.runtime.openOptionsPage());
refresh();
