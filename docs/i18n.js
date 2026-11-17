/* safe-url-guard web: UI text in English and Simplified Chinese.
 * SPDX-License-Identifier: GPL-3.0-or-later */
(function (root) {
  "use strict";
  var M = {
    en: {
      title: "Scam Checker | safe-url-guard",
      h1: "Scam Checker",
      lead: "Paste a suspicious message, link or QR code here and check it before you reply, pay or open anything.",
      tab_msg: "Message", tab_url: "Link", tab_qr: "QR code",
      msg_label: "Paste the SMS, LINE, e-mail or DM you received:",
      msg_ph: "e.g. Darling, I have insider information. This platform is guaranteed profit, just top up a little first...",
      msg_btn: "Check message",
      url_label: "Enter a link:",
      url_rdap: "Look up when the domain was registered (sends the domain name to public RDAP servers)",
      url_btn: "Check link",
      qr_label: "Choose a QR-code image (screenshot or photo):",
      qr_hint: "You can also paste a screenshot on this page with Ctrl+V / ⌘+V.",
      signs_h: "Common warning signs",
      sign_inv: "<b>Investment:</b> \"guaranteed profit\", \"risk-free\", \"mentor\", \"insider information\", and <b>paying tax, fees or a deposit before you can withdraw</b> (you will not get the money out)",
      sign_job: "<b>Jobs:</b> earning money for likes or orders, <b>paying first and getting a commission back</b>, \"easy money from home with your phone\"",
      sign_rom: "<b>Romance:</b> someone you met online and never met in person quickly says they love you or want to marry you, then <b>asks for money or recommends an investment</b> (\"pig butchering\")",
      sign_hook: "<b>\"Credit score\" / refund scams:</b> after you pay a fee or deposit on some platform, they say you made an <b>\"operation error\", your \"credit score\" is too low or your account is \"locked\"</b> and you must pay to \"restore\" it before a refund or withdrawal. <b>No matter how much you pay, nothing comes back.</b>",
      sign_common: "<b>All of them:</b> pressure to decide right now, <b>\"don't tell your family\"</b>, moving you to private chats on LINE, Telegram, WhatsApp etc.",
      help_h: "If you think you have been scammed",
      help_stop: "Stop paying. Keep all chats and payment records.",
      help_jp: "Japan: police consultation <b>#9110</b>, consumer hotline <b>188</b>; emergency <b>110</b>",
      help_cn: "Mainland China: anti-fraud hotline <b>96110</b>; emergency <b>110</b>",
      help_other: "Elsewhere: contact your local police and your bank as soon as possible",
      help_recovery: "Beware of anyone who offers to <b>\"recover your lost money\"</b>: that is often a second scam",
      privacy: "Messages and images are checked only inside your browser and are never uploaded. Domain names are sent to public RDAP servers only when \"look up when the domain was registered\" is ticked.",
      disclaimer: "* This tool looks for common scam tactics. The result does not prove that something is or is not a scam. If something feels wrong, talk to someone you trust or the police first.",
      footer_qr: "QR decoding by",
      level: ["No obvious scam signs found", "Risk: LOW", "Risk: MEDIUM, be careful", "Risk: HIGH, very likely a scam"],
      found: "Warning signs found", matched: "Matched:", combos: "Dangerous combinations",
      urls_in_msg: "Links in the message", url_age_hint: "To check when a link's domain was registered, paste it into the \"Link\" tab.",
      advice: "What to do",
      low_hint: "No common scam phrases were found, but that does not mean it is safe. If someone asks for money or a verification code, or tells you \"don't tell anyone\", talk to someone first.",
      rules_failed: "Could not load the rules file: ",
      url_danger: "DANGER: confirmed scam site", url_warn: "Suspicious traits found", url_ok: "No obvious suspicious traits found",
      builtin_hit: "⛔ {d} is a confirmed scam site (on this tool's built-in blocklist). Do not open it.",
      rdap_loading: "Looking up the registration date...",
      no_blocklist: "The web version cannot check the malware / phishing blocklists. For that, use the browser extension or the Python tool, and keep your browser's built-in Safe Browsing protection on.",
      lookup: " You can look it up manually at <a href=\"https://lookup.icann.org/\" target=\"_blank\" rel=\"noopener\">ICANN Lookup</a>.",
      rdap_ip: "This is an IP address; it has no registration date.",
      rdap_no_tld: "This domain ending is not in IANA's RDAP list, so it cannot be looked up automatically.",
      rdap_not_found: "The domain was not found in RDAP.",
      rdap_no_date: "The RDAP data has no registration date.",
      rdap_reg: "{d} was registered on {date} ({days} days ago)",
      rdap_danger: ": registered less than 1 month ago, very suspicious",
      rdap_warn: ": registered less than 6 months ago, be careful",
      rdap_old: " (an old domain is not proof of safety)",
      rdap_fail: "Could not look up the registration date ({e}).",
      qr_reading: "Reading...",
      qr_none: "No QR code found. Try a clearer image, or crop it to just the QR code.",
      qr_url_h: "Link inside the QR code",
      qr_url_hint: "Only open it once you are sure it is safe. Never type passwords or card details into a page opened from a QR code.",
      qr_text_h: "QR code content (not a link)",
      qr_bad_img: "Could not read this image.",
      h_bad: "Cannot parse this link",
      h_http: "Does not use HTTPS (connection is not encrypted)",
      h_ip: "Uses a raw IP address instead of a domain name",
      h_idn: "Domain contains special characters (punycode / xn--); it may imitate another site with look-alike letters",
      h_at: "Link contains '@'; the real destination may differ from what it looks like",
      h_sub: "Too many subdomain levels",
      h_long: "Unusually long link",
      h_port: "Uses non-standard port {port}"
    },
    zh: {
      title: "防诈骗检查工具 | safe-url-guard",
      h1: "防诈骗检查工具",
      lead: "把可疑的消息、网址或二维码放进来检查一下，再决定要不要回复、付款或打开。",
      tab_msg: "消息检查", tab_url: "网址检查", tab_qr: "二维码检查",
      msg_label: "粘贴收到的短信、LINE、邮件、私信内容：",
      msg_ph: "例：亲爱的，我有个内部消息，这个平台稳赚不赔，你先充值试试……",
      msg_btn: "检查消息",
      url_label: "输入网址：",
      url_rdap: "查询域名注册时间（会把域名发给公开的 RDAP 服务器）",
      url_btn: "检查网址",
      qr_label: "选择二维码图片（截图或照片）：",
      qr_hint: "也可以直接在这个页面按 Ctrl+V / ⌘+V 粘贴截图。",
      signs_h: "常见的诈骗危险信号",
      sign_inv: "<b>投资：</b>“稳赚不赔”“保本”“老师带单”“内部消息”，以及<b>提现前要先交税、手续费或保证金</b>（交了也提不出来）",
      sign_job: "<b>兼职：</b>点赞、刷单赚钱，<b>先垫付再返佣</b>，“在家用手机轻松日赚”",
      sign_rom: "<b>感情：</b>网上认识、没见过面，却很快说爱你、说要结婚，然后<b>借钱或推荐投资</b>（“杀猪盘”）",
      sign_hook: "<b>“信誉分 / 退款”诈骗：</b>在某个平台交了会员费或押金后，对方说你<b>“操作失误”“信誉分不足”“账户锁定”</b>，要你花钱“补信誉分”才能退款或提现。<b>补多少都不会退。</b>",
      sign_common: "<b>共同点：</b>催你马上做决定，叫你<b>“不要告诉家人”</b>，把你引到 LINE、Telegram、WhatsApp 等私聊",
      help_h: "觉得可能被骗了",
      help_stop: "先停止付款，保存好聊天记录和转账记录",
      help_jp: "日本：警察相谈专线 <b>#9110</b>、消费者热线 <b>188</b>；紧急情况拨 <b>110</b>",
      help_cn: "中国大陆：全国反诈专线 <b>96110</b>；紧急情况拨 <b>110</b>",
      help_other: "其他国家和地区：尽快联系当地警察和你的银行",
      help_recovery: "当心声称能帮你<b>“追回被骗的钱”</b>的人，这往往是第二次诈骗",
      privacy: "消息和图片只在你的浏览器里检查，不会上传。只有勾选“查询域名注册时间”时，域名才会发送给公开的 RDAP 服务器。",
      disclaimer: "※ 本工具根据常见手法判断，结果不代表一定是或一定不是诈骗。觉得不对劲时，请先找身边的人或警察商量。",
      footer_qr: "二维码识别使用",
      level: ["未发现明显的诈骗特征", "风险：低", "风险：中，请小心", "风险：高，很可能是诈骗"],
      found: "发现的特征", matched: "命中：", combos: "危险的组合",
      urls_in_msg: "消息中的网址", url_age_hint: "想查网址的注册时间，可以复制到“网址检查”里查。",
      advice: "建议",
      low_hint: "没有发现常见话术，不代表一定安全。只要对方要钱、要验证码，或者叫你“别告诉别人”，请先找人商量。",
      rules_failed: "规则文件加载失败：",
      url_danger: "危险：已确认的诈骗网站", url_warn: "有可疑特征", url_ok: "没有发现明显的可疑特征",
      builtin_hit: "⛔ {d} 是已经确认的诈骗网站（在本工具的内置黑名单中），千万不要打开",
      rdap_loading: "正在查询域名注册时间……",
      no_blocklist: "网页版无法比对恶意 / 钓鱼网站黑名单。需要比对的话，请用浏览器扩展或 Python 版工具，并开着浏览器自带的安全浏览保护。",
      lookup: " 可以在 <a href=\"https://lookup.icann.org/\" target=\"_blank\" rel=\"noopener\">ICANN Lookup</a> 手动查询。",
      rdap_ip: "这是 IP 地址，无法查询注册时间。",
      rdap_no_tld: "IANA 的 RDAP 列表中没有这个域名后缀，无法自动查询。",
      rdap_not_found: "RDAP 中找不到这个域名。",
      rdap_no_date: "RDAP 数据中没有注册日期。",
      rdap_reg: "{d} 注册于 {date}（{days} 天前）",
      rdap_danger: "：注册不到 1 个月，非常可疑",
      rdap_warn: "：注册不到半年，请小心",
      rdap_old: "（老域名也不代表一定安全）",
      rdap_fail: "无法查询注册时间（{e}）。",
      qr_reading: "正在识别……",
      qr_none: "没有识别到二维码。请换一张更清晰的图片，或只截取二维码部分。",
      qr_url_h: "二维码里的网址",
      qr_url_hint: "确认没问题后再打开。不要在扫码打开的页面里输入密码或银行卡信息。",
      qr_text_h: "二维码内容（不是网址）",
      qr_bad_img: "无法读取这张图片。",
      h_bad: "无法解析这个网址",
      h_http: "未使用 HTTPS（通信未加密）",
      h_ip: "直接使用 IP 地址而不是域名",
      h_idn: "域名含有特殊字符（punycode / xn--），可能是用相似字符仿冒的网站",
      h_at: "网址中含有 '@'，真实目标可能与看起来的不同",
      h_sub: "子域名层级过多",
      h_long: "网址异常地长",
      h_port: "使用非标准端口 {port}"
    }
  };

  function detect() {
    try {
      var q = new URLSearchParams(location.search).get("lang");
      if (q === "en" || q === "zh") return q;
      var saved = localStorage.getItem("sug-lang");
      if (saved === "en" || saved === "zh") return saved;
    } catch (e) { /* storage may be unavailable */ }
    return /^zh/i.test(navigator.language || "") ? "zh" : "en";
  }

  var I18N = {
    lang: detect(),
    messages: M,
    t: function (key, vars) {
      var s = (M[I18N.lang] && M[I18N.lang][key]) || M.en[key] || key;
      if (vars && typeof s === "string") {
        s = s.replace(/\{(\w+)\}/g, function (_, k) { return vars[k] != null ? vars[k] : ""; });
      }
      return s;
    },
    set: function (lang) {
      I18N.lang = lang;
      try { localStorage.setItem("sug-lang", lang); } catch (e) { /* ignore */ }
      I18N.apply();
    },
    apply: function () {
      document.documentElement.lang = I18N.lang === "zh" ? "zh-CN" : "en";
      document.title = I18N.t("title");
      document.querySelectorAll("[data-i18n]").forEach(function (el) { el.innerHTML = I18N.t(el.dataset.i18n); });
      document.querySelectorAll("[data-i18n-ph]").forEach(function (el) { el.placeholder = I18N.t(el.dataset.i18nPh); });
      document.querySelectorAll("[data-lang]").forEach(function (b) {
        b.setAttribute("aria-pressed", String(b.dataset.lang === I18N.lang));
      });
    }
  };
  root.I18N = I18N;
})(this);
