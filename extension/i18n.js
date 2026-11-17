/* safe-url-guard extension: UI text in English and Simplified Chinese.
 * The language follows the browser UI language unless changed on the options page.
 * SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
(function (root) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const M = {
    en: {
      blocked_title: "Dangerous site blocked",
      blocked_h1: "⛔ Dangerous site blocked",
      blocked_lead: "This site is on a public <b>malware / phishing (scam) blocklist</b>, so access was blocked.",
      blocked_li1: "Sites like this may install malware or steal your passwords, card details and money.",
      blocked_li2: "If someone sent you this link (SMS, LINE, e-mail, DM...), they are very likely a scammer. <b>Do not reply and do not pay.</b>",
      blocked_li3: "If you already typed a password or card number, change the password right away in the <b>official app or website</b> and contact your bank or card company.",
      blocked_help: "Help: Japan: police consultation <b>#9110</b>, consumer hotline <b>188</b> | Mainland China: anti-fraud hotline <b>96110</b> | Emergency: <b>110</b> | Elsewhere: your local police",
      blocked_back: "Go back to safety",
      blocked_src: "Blocklists: <a href=\"https://urlhaus.abuse.ch/\" target=\"_blank\" rel=\"noopener\">URLhaus</a> / <a href=\"https://openphish.com/\" target=\"_blank\" rel=\"noopener\">OpenPhish</a> / built-in list. Blocked by the safe-url-guard extension.",
      popup_blocking: "Blocking <span class=\"big\" id=\"count\">-</span> dangerous sites",
      popup_update: "Update now", popup_updating: "Updating…", popup_options: "Settings",
      popup_web: "Check suspicious messages or QR codes with the <a href=\"https://teikaki4399-hash.github.io/safe-url-guard/\" target=\"_blank\" rel=\"noopener\">web checker</a>.",
      popup_status_fail: "Could not read the status",
      popup_never: "never",
      popup_last: "Last update check: {t} (updates automatically every 24 hours)",
      popup_feed: "{label}: {n} ({t})",
      popup_feed_err: "Last update failed: {e}",
      feed_urlhaus: "URLhaus (malware)", feed_openphish: "OpenPhish (phishing)",
      opt_title: "safe-url-guard settings",
      opt_lang: "Language",
      opt_deny_h: "Custom blocklist",
      opt_deny_p: "Extra sites to block, one domain per line (e.g. <code>bad-shop.example</code>). Subdomains are blocked too. You can add sites scammers have used.",
      opt_allow_h: "Allowlist (exceptions)",
      opt_allow_p: "Only use this if a site you are <b>sure is safe</b> was blocked by mistake. One domain per line. The block page has no \"continue anyway\" button; this is the only way to allow a site.",
      opt_save: "Save",
      opt_saved: "Saved (blocking {n} sites)",
      opt_save_fail: "Save failed: {e}"
    },
    zh: {
      blocked_title: "已拦截危险网站",
      blocked_h1: "⛔ 已拦截危险网站",
      blocked_lead: "这个网站在公开的<b>恶意软件 / 钓鱼（诈骗）网站黑名单</b>中，已为你阻止访问。",
      blocked_li1: "这类网站可能会让你下载病毒，或者骗走密码、银行卡信息和钱。",
      blocked_li2: "如果链接是别人发给你的（短信、LINE、邮件、私信等），对方很可能是骗子。<b>不要回复，也不要付款。</b>",
      blocked_li3: "如果已经输入了密码或卡号，请马上在<b>官方 App 或官方网站</b>修改密码，并联系银行或发卡公司。",
      blocked_help: "咨询窗口　日本：警察相谈专线 <b>#9110</b>、消费者热线 <b>188</b>　｜　中国大陆：反诈专线 <b>96110</b>　｜　紧急情况：<b>110</b>",
      blocked_back: "返回安全的页面",
      blocked_src: "黑名单来源：<a href=\"https://urlhaus.abuse.ch/\" target=\"_blank\" rel=\"noopener\">URLhaus</a> / <a href=\"https://openphish.com/\" target=\"_blank\" rel=\"noopener\">OpenPhish</a> / 内置黑名单，由 safe-url-guard 扩展拦截。",
      popup_blocking: "正在拦截 <span class=\"big\" id=\"count\">-</span> 个危险网站",
      popup_update: "立即更新", popup_updating: "更新中…", popup_options: "设置",
      popup_web: "可疑的消息或二维码可以用<a href=\"https://teikaki4399-hash.github.io/safe-url-guard/?lang=zh\" target=\"_blank\" rel=\"noopener\">网页版检查工具</a>检查。",
      popup_status_fail: "读取状态失败",
      popup_never: "尚未更新",
      popup_last: "上次检查更新：{t}（每 24 小时自动更新）",
      popup_feed: "{label}：{n} 个（{t}）",
      popup_feed_err: "上次更新失败：{e}",
      feed_urlhaus: "URLhaus（恶意软件）", feed_openphish: "OpenPhish（钓鱼网站）",
      opt_title: "safe-url-guard 设置",
      opt_lang: "语言 / Language",
      opt_deny_h: "自定义黑名单",
      opt_deny_p: "想额外拦截的网站，每行一个域名（例：<code>bad-shop.example</code>），子域名也会一起拦截。可以把骗子用过的网站加进来。",
      opt_allow_h: "白名单（例外）",
      opt_allow_p: "只有在<b>确定安全</b>的网站被误拦截时才使用，每行一个域名。拦截页面上没有“仍要访问”的按钮，要放行只能在这里设置。",
      opt_save: "保存",
      opt_saved: "已保存（正在拦截 {n} 个网站）",
      opt_save_fail: "保存失败：{e}"
    }
  };

  const I18N = {
    lang: /^zh/i.test(api.i18n && api.i18n.getUILanguage ? api.i18n.getUILanguage() : navigator.language) ? "zh" : "en",
    t(key, vars) {
      let s = (M[I18N.lang] && M[I18N.lang][key]) || M.en[key] || key;
      if (vars) s = s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? vars[k] : ""));
      return s;
    },
    /* load the saved language (if any) and translate every [data-i18n] element */
    async init() {
      try {
        const { lang } = await api.storage.local.get("lang");
        if (lang === "en" || lang === "zh") I18N.lang = lang;
      } catch (e) { /* use the browser language */ }
      document.documentElement.lang = I18N.lang === "zh" ? "zh-CN" : "en";
      document.querySelectorAll("[data-i18n]").forEach(el => { el.innerHTML = I18N.t(el.dataset.i18n); });
      return I18N.lang;
    }
  };
  root.I18N = I18N;
})(this);
