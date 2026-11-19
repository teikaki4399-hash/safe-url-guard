/*
 * safe-url-guard extension - content script (runs on every page, top frame only)
 *
 * "Stop and think before you transfer": when a page looks like an online-banking or
 * payment transfer page (transfer words in the address or headings AND an amount field),
 * show a short checklist of the questions that expose most transfer scams.
 * It never blocks the transfer; it only asks the user to stop and think once.
 *
 * Everything is drawn inside a closed shadow root so the page cannot read or restyle it.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
"use strict";
(function () {
  if (window.top !== window || !/^https?:$/.test(location.protocol)) return;
  const api = typeof browser !== "undefined" ? browser : chrome;
  const T = (k, v) => I18N.t(k, v);

  /* ---------- shared: one host element with a closed shadow root ---------- */
  let shadow = null;
  function root() {
    if (shadow) return shadow;
    const host = document.createElement("safe-url-guard-ui");
    host.style.cssText = "all: initial; position: static;";
    (document.body || document.documentElement).appendChild(host);
    shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = CSS;
    shadow.appendChild(style);
    return shadow;
  }
  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;   // only our own translated strings, never page text
    return e;
  }

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", "Hiragino Sans", "PingFang SC", "Microsoft YaHei", sans-serif; }
    .overlay { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.55);
      display: flex; align-items: flex-start; justify-content: center; overflow-y: auto; padding: 4vh 12px; }
    .dlg { background: #fff; color: #1d2330; max-width: 600px; width: 100%; border-radius: 14px;
      border-top: 8px solid #c62828; padding: 20px 24px; line-height: 1.6; font-size: 16px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
    h2 { margin: 0 0 6px; font-size: 22px; color: #c62828; }
    p { margin: 6px 0; }
    .rule { background: #fdecea; color: #b71c1c; border-radius: 8px; padding: 10px 12px; font-weight: 700; margin: 10px 0; }
    ol { padding-left: 1.3em; margin: 10px 0; }
    li { margin: 10px 0; }
    .yn { display: flex; gap: 8px; margin-top: 4px; }
    button { font: inherit; font-size: 15px; padding: 7px 16px; border-radius: 8px; border: 1px solid #b8c0cc;
      background: #fff; color: #1d2330; cursor: pointer; }
    button[aria-pressed="true"].yes { background: #c62828; border-color: #c62828; color: #fff; }
    button[aria-pressed="true"].no { background: #1e7d43; border-color: #1e7d43; color: #fff; }
    button.primary { background: #2456c7; border-color: #2456c7; color: #fff; font-weight: 700; }
    button.stop { background: #c62828; border-color: #c62828; color: #fff; font-weight: 700; }
    button:disabled { opacity: .5; cursor: default; }
    .result { border-radius: 8px; padding: 10px 12px; margin: 10px 0; }
    .danger { background: #fdecea; color: #b71c1c; }
    .ok { background: #e8f5ed; color: #1e5c34; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
    .muted { color: #5d6576; font-size: 13px; }
    .bar { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646; background: #b71c1c; color: #fff;
      padding: 10px 48px 10px 16px; font-size: 15px; line-height: 1.5; box-shadow: 0 2px 10px rgba(0,0,0,.3); }
    .bar b { color: #fff; }
    .bar .x { position: absolute; top: 6px; right: 8px; background: transparent; border: 1px solid #fff; color: #fff; padding: 2px 10px; }
    @media (prefers-color-scheme: dark) {
      .dlg { background: #1e232b; color: #e6e9ef; }
      button { background: #262c36; color: #e6e9ef; border-color: #4a5260; }
      .muted { color: #a0a8b8; }
      .rule, .danger { background: #3a1f1f; color: #ffb4ab; }
      .ok { background: #1b3326; color: #9fe0b5; }
    }`;

  /* =====================================================================
   * 1. "Stop and think before you transfer" checklist
   * ===================================================================== */
  // words that mean "transfer / send money" (Japanese, Chinese, English)
  const TRANSFER_WORDS = /振込|振り込み|振替|送金|仕送り|转账|轉帳|轉賬|汇款|匯款|打款|付款给|transfer (money|funds)|money transfer|send money|wire transfer|make a transfer|new payee|add payee|remittance/i;
  const TRANSFER_URL = /transfer|furikomi|furikae|soukin|remit|send-?money|payee|zhuanzhang|huikuan/i;
  // amount field: number-like input, or a label / name that says "amount"
  const AMOUNT_WORDS = /amount|金額|金额|kingaku|jine|円|¥|￥|元/i;
  const QUESTIONS = ["tc_q1", "tc_q2", "tc_q3", "tc_q4", "tc_q5", "tc_q6", "tc_q7"];

  function visible(e) {
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }
  function hasAmountField() {
    const inputs = document.querySelectorAll("input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=search]):not([type=password])");
    for (const i of inputs) {
      if (!visible(i)) continue;
      if (i.type === "number" || /numeric|decimal/.test(i.inputMode || "")) return true;
      const label = [i.name, i.id, i.placeholder, i.getAttribute("aria-label"),
        i.labels && i.labels[0] && i.labels[0].textContent].join(" ");
      if (AMOUNT_WORDS.test(label)) return true;
    }
    return false;
  }
  function headingText() {
    const parts = [document.title];
    document.querySelectorAll("h1, h2, h3, legend, [role=heading]").forEach((h, n) => {
      if (n < 40) parts.push(h.textContent.slice(0, 200));
    });
    return parts.join(" \n ");
  }
  function looksLikeTransferPage() {
    const urlHit = TRANSFER_URL.test(location.pathname + location.search + location.hash);
    return (urlHit || TRANSFER_WORDS.test(headingText())) && hasAmountField();
  }

  let checklistShown = false;
  function alreadyShownForSite() {
    try { return sessionStorage.getItem("safe-url-guard-transfer") === "1"; } catch (e) { return false; }
  }
  function rememberShown() {
    checklistShown = true;
    try { sessionStorage.setItem("safe-url-guard-transfer", "1"); } catch (e) { /* ignore */ }
  }

  function showChecklist() {
    rememberShown();
    const ov = el("div", "overlay");
    const dlg = el("div", "dlg");
    dlg.setAttribute("role", "dialog");
    dlg.setAttribute("aria-modal", "true");
    dlg.appendChild(el("h2", null, T("tc_title")));
    dlg.appendChild(el("p", null, T("tc_lead")));
    const ol = el("ol");
    const answers = {};
    QUESTIONS.forEach(q => {
      const li = el("li", null, T(q));
      const yn = el("div", "yn");
      const yes = el("button", "yes", T("tc_yes"));
      const no = el("button", "no", T("tc_no"));
      [yes, no].forEach(b => { b.type = "button"; b.setAttribute("aria-pressed", "false"); });
      yes.addEventListener("click", () => answer(q, true, yes, no));
      no.addEventListener("click", () => answer(q, false, no, yes));
      yn.append(yes, no);
      li.appendChild(yn);
      ol.appendChild(li);
    });
    dlg.appendChild(ol);
    const result = el("div");
    dlg.appendChild(result);
    const row = el("div", "row");
    const stop = el("button", "stop", T("tc_stop"));
    const go = el("button", "primary", T("tc_continue"));
    stop.type = go.type = "button";
    go.disabled = true;
    row.append(stop, go);
    dlg.appendChild(row);
    dlg.appendChild(el("p", "muted", T("tc_note")));
    ov.appendChild(dlg);
    root().appendChild(ov);
    stop.focus();

    let timer = null;
    function answer(q, value, on, off) {
      answers[q] = value;
      on.setAttribute("aria-pressed", "true");
      off.setAttribute("aria-pressed", "false");
      if (Object.keys(answers).length < QUESTIONS.length) return;
      clearInterval(timer);
      if (QUESTIONS.some(k => answers[k])) {
        result.className = "result danger";
        result.innerHTML = T("tc_danger");
        // a short pause: scammers rely on hurry, so make "continue" wait a little
        let left = 15;
        go.disabled = true;
        go.textContent = T("tc_wait", { n: left });
        timer = setInterval(() => {
          left -= 1;
          if (left > 0) { go.textContent = T("tc_wait", { n: left }); return; }
          clearInterval(timer);
          go.disabled = false;
          go.textContent = T("tc_continue_anyway");
        }, 1000);
      } else {
        result.className = "result ok";
        result.innerHTML = T("tc_ok");
        go.disabled = false;
        go.textContent = T("tc_continue");
      }
    }
    function close() { clearInterval(timer); ov.remove(); }
    go.addEventListener("click", close);
    stop.addEventListener("click", () => {
      close();
      if (history.length > 1) history.back();
    });
  }

  function checkTransfer() {
    if (checklistShown || alreadyShownForSite()) return;
    if (looksLikeTransferPage()) showChecklist();
  }

  /* ---------- start ---------- */
  Promise.all([I18N.load(), api.storage.local.get(["transferCheck"])]).then(([, st]) => {
    if (st.transferCheck !== false) {             // can be turned off on the options page
      checkTransfer();
      // banking sites are often single-page apps: re-check (at most once a second) when the page changes
      let pending = null;
      const obs = new MutationObserver(() => {
        if (checklistShown) { obs.disconnect(); return; }
        if (!pending) pending = setTimeout(() => { pending = null; checkTransfer(); }, 1000);
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
    }
  });
})();
