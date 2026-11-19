/* safe-url-guard extension: UI text in English, Simplified Chinese and Japanese.
 * The language follows the browser UI language unless changed on the options page.
 * SPDX-License-Identifier: GPL-3.0-or-later */
"use strict";
(function (root) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const M = {
    en: {
      golden: "<b>The most important rule:</b> <b>\"You must pay first to get your money back\" = 100% a scam.</b> Whatever they call it (fee, tax, deposit, unfreeze charge, \"credit score\"), if you must pay before you can get a refund, withdraw or get your money back, it is a scam.",
      blocked_title: "Dangerous site blocked",
      blocked_h1: "⛔ Dangerous site blocked",
      blocked_lead: "This site is on a public <b>malware / phishing (scam) blocklist</b>, so access was blocked.",
      blocked_li1: "Sites like this may install malware or steal your passwords, card details and money.",
      blocked_li2: "If someone sent you this link (SMS, LINE, e-mail, DM...), they are very likely a scammer. <b>Do not reply and do not pay.</b>",
      blocked_li3: "If you already typed a password or card number, change the password right away in the <b>official app or website</b> and contact your bank or card company.",
      blocked_help: "Help: Japan: police consultation <b>#9110</b>, consumer hotline <b>188</b> | Mainland China: anti-fraud hotline <b>96110</b> | Emergency: <b>110</b> | Elsewhere: your local police",
      blocked_back: "Go back to safety",
      blocked_src: "Blocklists: <a href=\"https://openphish.com/\" target=\"_blank\" rel=\"noopener\">OpenPhish</a> / <a href=\"https://github.com/hagezi/dns-blocklists\" target=\"_blank\" rel=\"noopener\">HaGeZi Threat Intelligence Feeds</a> / built-in list. Blocked by the safe-url-guard extension.",
      popup_blocking: "Blocking <span class=\"big\" id=\"count\">-</span> dangerous sites",
      popup_update: "Update now", popup_updating: "Updating…", popup_options: "Settings",
      popup_web: "Check suspicious messages or QR codes with the <a href=\"https://teikaki4399-hash.github.io/safe-url-guard/\" target=\"_blank\" rel=\"noopener\">web checker</a>.",
      popup_status_fail: "Could not read the status",
      popup_never: "never",
      popup_last: "Last update check: {t} (updates automatically every 24 hours)",
      popup_feed: "{label}: {n} ({t})",
      popup_feed_err: "Last update failed: {e}",
      feed_openphish: "OpenPhish (phishing)", feed_hagezi_tif: "HaGeZi TIF (malware / phishing / scams)",
      opt_title: "safe-url-guard settings",
      opt_lang: "Language",
      opt_deny_h: "Custom blocklist",
      opt_deny_p: "Extra sites to block, one domain per line (e.g. <code>bad-shop.example</code>). Subdomains are blocked too. You can add sites scammers have used.",
      opt_allow_h: "Allowlist (exceptions)",
      opt_allow_p: "Only use this if a site you are <b>sure is safe</b> was blocked by mistake. One domain per line. The block page has no \"continue anyway\" button; this is the only way to allow a site.",
      opt_save: "Save",
      opt_saved: "Saved (blocking {n} sites)",
      opt_save_fail: "Save failed: {e}",
      opt_transfer_h: "\"Stop and think before you transfer\" checklist",
      opt_transfer_p: "When a page looks like an online-banking or payment transfer page, show a short checklist once per site and browser session. It never blocks the transfer.",
      opt_on: "Turn on",
      opt_newdom_h: "Warning bar for new domains",
      opt_newdom_p: "When the site you open was registered less than 30 days ago, show a warning bar at the top of the page (it does not block). To do this, the extension sends the domain name (not the full address) of the sites you open to the public RDAP server of that domain ending. Results are cached, so each domain is looked up at most about once a month.",
      nd_bar: "⚠ <b>Warning: this site is brand new.</b> {d} was registered on {date}, only <b>{days} days ago</b>. Many scam sites start scamming soon after they are registered. Do not enter passwords or card details here and do not pay.",
      nd_close: "Close",
      tc_title: "🛑 Stop and think before you transfer",
      tc_lead: "This page looks like a money transfer page. Before you send money, please answer these questions honestly.",
      tc_q1: "Is the person you are paying someone you <b>met online and have never met in person</b>?",
      tc_q2: "Did they say you must <b>pay first</b> (a fee, tax, deposit or \"unfreeze\" charge) <b>before you can get a refund or withdraw</b>?",
      tc_q3: "Did they tell you <b>not to tell</b> your family, friends or the bank?",
      tc_q4: "Are they <b>hurrying</b> you (\"today only\", \"or it will be too late\")?",
      tc_q5: "Do they say they are the <b>police, a prosecutor, a bank or a government office</b> and ask you to move money to a \"safe account\"?",
      tc_q6: "Is this payment for an <b>investment, a task/part-time job, a prize</b> or to restore a \"credit score\"?",
      tc_q7: "Is someone <b>guiding you step by step</b> by phone or chat right now, or asking you to share your screen or install an app?",
      tc_yes: "Yes", tc_no: "No",
      tc_danger: "<b>⚠ This is very likely a scam. Do not transfer the money.</b><br>Stop replying, hang up, and talk to your family or the police first. Japan: police consultation <b>#9110</b>, consumer hotline <b>188</b> | Mainland China: anti-fraud hotline <b>96110</b> | Emergency: <b>110</b>",
      tc_ok: "No warning signs from these questions. If anything still feels wrong, stop and talk to someone before you send money.",
      tc_stop: "Stop, do not transfer",
      tc_continue: "Continue",
      tc_wait: "Please wait {n}s…",
      tc_continue_anyway: "I have checked with someone; continue",
      tc_note: "safe-url-guard extension. This checklist only asks; it never blocks the transfer. It can be turned off in the extension's settings."
    },
    zh: {
      golden: "<b>最重要的一条：</b><b>“要先付钱，才能拿回钱”＝ 100% 是诈骗。</b>不管对方说是手续费、税、保证金、解冻费还是“补信誉分”，只要是要你先付钱才能退款、提现或拿回钱，就是诈骗。",
      blocked_title: "已拦截危险网站",
      blocked_h1: "⛔ 已拦截危险网站",
      blocked_lead: "这个网站在公开的<b>恶意软件 / 钓鱼（诈骗）网站黑名单</b>中，已为你阻止访问。",
      blocked_li1: "这类网站可能会让你下载病毒，或者骗走密码、银行卡信息和钱。",
      blocked_li2: "如果链接是别人发给你的（短信、LINE、邮件、私信等），对方很可能是骗子。<b>不要回复，也不要付款。</b>",
      blocked_li3: "如果已经输入了密码或卡号，请马上在<b>官方 App 或官方网站</b>修改密码，并联系银行或发卡公司。",
      blocked_help: "咨询窗口　日本：警察相谈专线 <b>#9110</b>、消费者热线 <b>188</b>　｜　中国大陆：反诈专线 <b>96110</b>　｜　紧急情况：<b>110</b>",
      blocked_back: "返回安全的页面",
      blocked_src: "黑名单来源：<a href=\"https://openphish.com/\" target=\"_blank\" rel=\"noopener\">OpenPhish</a> / <a href=\"https://github.com/hagezi/dns-blocklists\" target=\"_blank\" rel=\"noopener\">HaGeZi Threat Intelligence Feeds</a> / 内置黑名单，由 safe-url-guard 扩展拦截。",
      popup_blocking: "正在拦截 <span class=\"big\" id=\"count\">-</span> 个危险网站",
      popup_update: "立即更新", popup_updating: "更新中…", popup_options: "设置",
      popup_web: "可疑的消息或二维码可以用<a href=\"https://teikaki4399-hash.github.io/safe-url-guard/?lang=zh\" target=\"_blank\" rel=\"noopener\">网页版检查工具</a>检查。",
      popup_status_fail: "读取状态失败",
      popup_never: "尚未更新",
      popup_last: "上次检查更新：{t}（每 24 小时自动更新）",
      popup_feed: "{label}：{n} 个（{t}）",
      popup_feed_err: "上次更新失败：{e}",
      feed_openphish: "OpenPhish（钓鱼网站）", feed_hagezi_tif: "HaGeZi TIF（恶意软件 / 钓鱼 / 诈骗）",
      opt_title: "safe-url-guard 设置",
      opt_lang: "语言 / Language",
      opt_deny_h: "自定义黑名单",
      opt_deny_p: "想额外拦截的网站，每行一个域名（例：<code>bad-shop.example</code>），子域名也会一起拦截。可以把骗子用过的网站加进来。",
      opt_allow_h: "白名单（例外）",
      opt_allow_p: "只有在<b>确定安全</b>的网站被误拦截时才使用，每行一个域名。拦截页面上没有“仍要访问”的按钮，要放行只能在这里设置。",
      opt_save: "保存",
      opt_saved: "已保存（正在拦截 {n} 个网站）",
      opt_save_fail: "保存失败：{e}",
      opt_transfer_h: "“转账前冷静一下”确认清单",
      opt_transfer_p: "打开看起来像网上银行或支付转账的页面时，每个网站在每次浏览器会话中弹出一次确认清单。不会阻止转账。",
      opt_on: "开启",
      opt_newdom_h: "新域名警告条",
      opt_newdom_p: "打开的网站注册不到 30 天时，在页面顶部显示警告条（不拦截）。为此，扩展会把你打开的网站的域名（不是完整网址）发送给该域名后缀的公开 RDAP 服务器。查询结果会缓存，同一个域名大约每月最多查询一次。",
      nd_bar: "⚠ <b>注意：这是刚注册的新网站。</b>{d} 注册于 {date}，只有 <b>{days} 天</b>。很多诈骗网站注册后不久就开始骗人。不要在这里输入密码或银行卡信息，也不要付款。",
      nd_close: "关闭",
      tc_title: "🛑 转账前冷静一下",
      tc_lead: "这个页面看起来是转账页面。付钱之前，请如实回答下面几个问题。",
      tc_q1: "收款人是<b>网上认识、没见过面</b>的人吗？",
      tc_q2: "对方说过要<b>先付钱</b>（手续费、税、保证金、解冻费等），<b>才能退款或提现</b>吗？",
      tc_q3: "对方叫你<b>别告诉</b>家人、朋友或银行吗？",
      tc_q4: "对方在<b>催你</b>（“只有今天”“再不转就来不及了”）吗？",
      tc_q5: "对方自称<b>警察、检察官、银行或政府机关</b>，要你把钱转到“安全账户”吗？",
      tc_q6: "这笔钱是为了<b>投资、兼职任务、领奖</b>，或者“补信誉分”吗？",
      tc_q7: "现在有人在电话或聊天里<b>一步步教你操作</b>，或者让你共享屏幕、安装 App 吗？",
      tc_yes: "是", tc_no: "否",
      tc_danger: "<b>⚠ 很可能是诈骗，请不要转账。</b><br>先停止回复、挂断电话，找家人或警察商量。日本：警察相谈专线 <b>#9110</b>、消费者热线 <b>188</b>　｜　中国大陆：反诈专线 <b>96110</b>　｜　紧急情况：<b>110</b>",
      tc_ok: "这些问题里没有发现危险信号。只要还有一点不对劲，就先停下来找人商量，再付钱。",
      tc_stop: "不转了，返回",
      tc_continue: "继续",
      tc_wait: "请等待 {n} 秒…",
      tc_continue_anyway: "我已经找人确认过，继续",
      tc_note: "safe-url-guard 扩展。这个清单只是提醒，不会阻止转账，可以在扩展的设置里关闭。"
    },
    ja: {
      golden: "<b>いちばん大切なルール：</b><b>「お金を取り戻すには、先に払う必要がある」＝ 100% 詐欺です。</b>手数料・税金・保証金・凍結解除料・「信用スコア」など名目が何であっても、返金・出金・お金を取り戻す前に払わせるのは詐欺です。",
      blocked_title: "危険なサイトをブロックしました",
      blocked_h1: "⛔ 危険なサイトをブロックしました",
      blocked_lead: "このサイトは公開されている<b>マルウェア・フィッシング（詐欺）サイトのブロックリスト</b>に載っているため、アクセスをブロックしました。",
      blocked_li1: "このようなサイトは、ウイルスを入れたり、パスワード・カード情報・お金をだまし取ったりするおそれがあります。",
      blocked_li2: "誰かから送られてきたリンク（SMS、LINE、メール、DMなど）なら、相手は詐欺師の可能性が非常に高いです。<b>返信せず、支払わないでください。</b>",
      blocked_li3: "すでにパスワードやカード番号を入力してしまった場合は、すぐに<b>公式アプリまたは公式サイト</b>でパスワードを変更し、銀行やカード会社に連絡してください。",
      blocked_help: "相談窓口　日本：警察相談専用電話 <b>#9110</b>、消費者ホットライン <b>188</b>　｜　中国本土：詐欺対策ホットライン <b>96110</b>　｜　緊急時：<b>110</b>　｜　その他の地域：地元の警察",
      blocked_back: "安全なページに戻る",
      blocked_src: "ブロックリスト：<a href=\"https://openphish.com/\" target=\"_blank\" rel=\"noopener\">OpenPhish</a> / <a href=\"https://github.com/hagezi/dns-blocklists\" target=\"_blank\" rel=\"noopener\">HaGeZi Threat Intelligence Feeds</a> / 内蔵リスト。safe-url-guard 拡張機能がブロックしました。",
      popup_blocking: "<span class=\"big\" id=\"count\">-</span> 件の危険なサイトをブロック中",
      popup_update: "今すぐ更新", popup_updating: "更新中…", popup_options: "設定",
      popup_web: "あやしいメッセージやQRコードは<a href=\"https://teikaki4399-hash.github.io/safe-url-guard/?lang=ja\" target=\"_blank\" rel=\"noopener\">ウェブ版チェッカー</a>でチェックできます。",
      popup_status_fail: "状態を読み込めませんでした",
      popup_never: "未更新",
      popup_last: "前回の更新確認：{t}（24時間ごとに自動更新）",
      popup_feed: "{label}：{n} 件（{t}）",
      popup_feed_err: "前回の更新に失敗しました：{e}",
      feed_openphish: "OpenPhish（フィッシング）", feed_hagezi_tif: "HaGeZi TIF（マルウェア・フィッシング・詐欺）",
      opt_title: "safe-url-guard の設定",
      opt_lang: "言語 / Language",
      opt_deny_h: "独自のブロックリスト",
      opt_deny_p: "追加でブロックしたいサイトを1行に1ドメインずつ入力します（例：<code>bad-shop.example</code>）。サブドメインもブロックされます。詐欺師が使ったサイトを追加できます。",
      opt_allow_h: "許可リスト（例外）",
      opt_allow_p: "<b>安全だと確実にわかっている</b>サイトが誤ってブロックされたときだけ使ってください。1行に1ドメイン。ブロック画面には「このまま進む」ボタンがないため、許可する方法はここだけです。",
      opt_save: "保存",
      opt_saved: "保存しました（{n} 件のサイトをブロック中）",
      opt_save_fail: "保存に失敗しました：{e}",
      opt_newdom_h: "新しいドメインの警告バー",
      opt_newdom_p: "開いたサイトが登録から30日未満のとき、ページ上部に警告バーを表示します（ブロックはしません）。そのために、開いたサイトのドメイン名（完全なアドレスではありません）を、そのドメインの末尾を管理する公開RDAPサーバーに送信します。結果はキャッシュされるため、同じドメインの問い合わせは月に1回程度です。",
      nd_bar: "⚠ <b>注意：できたばかりのサイトです。</b>{d} の登録日は {date}、まだ <b>{days} 日</b>しか経っていません。詐欺サイトの多くは登録から間もなく詐欺を始めます。ここでパスワードやカード情報を入力したり、支払ったりしないでください。",
      nd_close: "閉じる",
      opt_transfer_h: "「振り込む前にひと呼吸」チェックリスト",
      opt_transfer_p: "ネットバンキングや決済の振込・送金ページらしいページを開いたとき、サイトごと・ブラウザのセッションごとに1回、確認のチェックリストを表示します。振込をブロックすることはありません。",
      opt_on: "オンにする",
      tc_title: "🛑 振り込む前にひと呼吸",
      tc_lead: "このページは振込・送金のページのようです。お金を送る前に、次の質問に正直に答えてください。",
      tc_q1: "振込先は、<b>ネットで知り合い、会ったことのない人</b>ですか？",
      tc_q2: "<b>返金や出金の前に、先にお金（手数料・税金・保証金・凍結解除料など）を払う必要がある</b>と言われましたか？",
      tc_q3: "家族・友人・銀行には<b>言わないで</b>と言われましたか？",
      tc_q4: "「今日中に」「今すぐでないと間に合わない」と<b>急かされて</b>いますか？",
      tc_q5: "<b>警察・検察・銀行・役所</b>を名乗る相手から、「安全な口座」にお金を移すよう言われましたか？",
      tc_q6: "この振込は<b>投資・副業のタスク・賞金の受け取り</b>、または「信用スコアの回復」のためですか？",
      tc_q7: "今、電話やチャットで誰かが<b>一つずつ操作を指示</b>していますか？ または画面共有やアプリのインストールを求められましたか？",
      tc_yes: "はい", tc_no: "いいえ",
      tc_danger: "<b>⚠ 詐欺の可能性が非常に高いです。振り込まないでください。</b><br>返信をやめ、電話を切って、まず家族か警察に相談してください。日本：警察相談専用電話 <b>#9110</b>、消費者ホットライン <b>188</b>　｜　中国本土：詐欺対策ホットライン <b>96110</b>　｜　緊急時：<b>110</b>",
      tc_ok: "これらの質問では危険なサインは見つかりませんでした。それでも少しでもおかしいと感じたら、お金を送る前に止まって誰かに相談してください。",
      tc_stop: "振り込まずに戻る",
      tc_continue: "続ける",
      tc_wait: "{n} 秒お待ちください…",
      tc_continue_anyway: "誰かに相談して確認したので続ける",
      tc_note: "safe-url-guard 拡張機能。このチェックリストは確認するだけで、振込をブロックすることはありません。拡張機能の設定でオフにできます。"
    }
  };

  const I18N = {
    lang: (function () {
      const ui = api.i18n && api.i18n.getUILanguage ? api.i18n.getUILanguage() : navigator.language;
      return /^zh/i.test(ui) ? "zh" : /^ja/i.test(ui) ? "ja" : "en";
    })(),
    messages: M,
    locale() { return { zh: "zh-CN", ja: "ja", en: "en" }[I18N.lang] || "en"; },
    t(key, vars) {
      let s = (M[I18N.lang] && M[I18N.lang][key]) || M.en[key] || key;
      if (vars) s = s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? vars[k] : ""));
      return s;
    },
    /* load the saved language (if any); used by content scripts, which must not touch the page */
    async load() {
      try {
        const { lang } = await api.storage.local.get("lang");
        if (M[lang]) I18N.lang = lang;
      } catch (e) { /* use the browser language */ }
      return I18N.lang;
    },
    /* load the language and translate every [data-i18n] element of an extension page */
    async init() {
      await I18N.load();
      document.documentElement.lang = I18N.locale();
      document.querySelectorAll("[data-i18n]").forEach(el => { el.innerHTML = I18N.t(el.dataset.i18n); });
      return I18N.lang;
    }
  };
  root.I18N = I18N;
})(this);
