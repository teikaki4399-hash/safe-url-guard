/* SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
const api = typeof browser !== "undefined" ? browser : chrome;
const $ = id => document.getElementById(id);
const fmt = t => t ? new Date(t).toLocaleString(I18N.lang === "en" ? undefined : I18N.locale()) : I18N.t("popup_never");

function send(msg) {
  return new Promise(resolve => api.runtime.sendMessage(msg, resolve));
}

async function refresh() {
  const s = await send({ type: "status" });
  if (!s || s.error) { $("last").textContent = I18N.t("popup_status_fail"); return; }
  $("count").textContent = s.blockedCount.toLocaleString();
  $("feeds").innerHTML = "";
  for (const [name, f] of Object.entries(s.feeds)) {
    const li = document.createElement("li");
    li.textContent = I18N.t("popup_feed", { label: I18N.t("feed_" + name), n: f.count.toLocaleString(), t: fmt(f.updated) });
    if (f.error) {
      const e = document.createElement("div");
      e.className = "err";
      e.textContent = I18N.t("popup_feed_err", { e: f.error });
      li.appendChild(e);
    }
    $("feeds").appendChild(li);
  }
  $("last").textContent = I18N.t("popup_last", { t: fmt(s.lastAttempt) });
}

I18N.init().then(() => {
  $("update").addEventListener("click", async () => {
    $("update").disabled = true;
    $("update").textContent = I18N.t("popup_updating");
    await send({ type: "updateNow" });
    $("update").disabled = false;
    $("update").textContent = I18N.t("popup_update");
    refresh();
  });
  $("options").addEventListener("click", () => api.runtime.openOptionsPage());
  refresh();
});
