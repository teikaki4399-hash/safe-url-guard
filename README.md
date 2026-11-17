# safe-url-guard

防止被**病毒网站、钓鱼网站和诈骗消息**骗到的一组免费工具。

> 希望不再有人被骗。重点针对**同城约会（约炮）诈骗、投资诈骗、兼职刷单诈骗、感情（网恋）诈骗**。

| 工具 | 适合谁 | 能做什么 |
|---|---|---|
| 🧩 [浏览器扩展](#-浏览器扩展推荐) | 所有人（推荐） | 浏览器启动后自动运行，**访问危险网站时直接拦截**，点链接也会被挡住 |
| 🌐 [网页版检查工具](#-网页版检查工具) | 不会编程的人 | 打开网页，检查**可疑消息、网址、二维码** |
| 🐍 [Python 命令行工具](#-python-命令行工具) | 会用终端的人 | 和上面相同的检查，可以写进脚本里 |

---

## 🧩 浏览器扩展（推荐）

- 浏览器启动时自动运行，每 24 小时自动更新黑名单
- 打开黑名单上的网站（包括它的子域名）时，会跳转到警告页面，**页面上没有“仍要访问”的按钮**
- 可以自己添加要拦截的网站（自定义黑名单）；被误拦截时，可以在设置里加白名单

### 安装方法（Chrome / Edge）

1. 下载这个仓库：点页面上方绿色的 **Code → Download ZIP**，然后解压
2. 在地址栏输入 `chrome://extensions`（Edge 输入 `edge://extensions`）
3. 打开右上角的 **开发者模式**（Developer mode）
4. 点 **加载已解压的扩展程序**（Load unpacked），选择解压后的 `extension` 文件夹
5. 点工具栏上的 🛡 图标，能看到“正在拦截 ○○ 个危险网站”就说明安装成功了

> 安装时浏览器会提示扩展需要访问所有网站的权限。这是把危险网站**重定向到警告页面**所必需的（[Chrome 的说明](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)）。这个扩展不会读取网页内容，也不会把浏览记录发送到任何地方，所有代码都在这个仓库里公开。

Firefox 128 及以上版本：在 `about:debugging#/runtime/this-firefox` 里点“临时载入附加组件”，选择 `extension/manifest.json`。这种方式在浏览器重启后会失效。想一直使用的话，需要把扩展提交到 [addons.mozilla.org](https://addons.mozilla.org/) 签名。另外我目前只在 Chromium 上测试过。

## 🌐 网页版检查工具

网址：**https://teikaki4399-hash.github.io/safe-url-guard/**（启用 GitHub Pages 后可用）

- **消息检查**：粘贴短信、LINE、邮件、私信内容，检查里面有没有常见的诈骗话术
- **网址检查**：检查可疑特征（仿冒域名、IP 地址等），并查询域名注册了多久
- **二维码检查**：读取二维码图片里的网址，检查之后再决定要不要打开

消息和图片只在浏览器里检查，不会上传到服务器。

## 🐍 Python 命令行工具

需要 Python 3.8 以上版本，只用到标准库。二维码检查需要额外安装 OpenCV。

```sh
git clone https://github.com/teikaki4399-hash/safe-url-guard.git
cd safe-url-guard

# 网址检查（先下载黑名单，建议每天运行一次）
python3 safe_url_guard.py update
python3 safe_url_guard.py check https://example.com
python3 safe_url_guard.py open https://example.com     # 危险的网站会被拦截，可疑的会先询问
python3 safe_url_guard.py hosts > blocklist-hosts.txt  # 生成 hosts 文件格式的拦截列表

# 诈骗消息检查
python3 scam_check.py "亲爱的，这个平台稳赚不赔，先充值试试"
python3 scam_check.py -f message.txt --online           # --online：顺便查询消息中网址的注册时间

# 域名注册时间
python3 domain_age.py https://shop.example.com

# 二维码检查
pip install opencv-python-headless
python3 qr_check.py qr.png
```

自定义列表放在 `~/.cache/safe_url_guard/` 下：`allowlist.txt` 是白名单，`denylist.txt` 是黑名单，每行写一个域名。

## 判断依据

| 检查内容 | 依据 |
|---|---|
| 恶意软件网站 | [URLhaus](https://urlhaus.abuse.ch/)（abuse.ch）的公开黑名单 |
| 钓鱼网站 | [OpenPhish](https://openphish.com/phishing_feeds.html) 的公开黑名单（Community Feed） |
| 域名注册时间 | [RDAP](https://www.icann.org/rdap)（RFC 9082/9083），通过 [IANA bootstrap](https://data.iana.org/rdap/dns.json) 找到对应的查询服务器。注册不到 30 天判为“非常可疑”，不到 180 天判为“请小心” |
| 诈骗话术 | [`docs/scam_rules.json`](docs/scam_rules.json) 里的规则，按特征打分，并对危险的组合额外加分，例如“感情 + 要钱”“兼职 + 先垫付” |

## 局限性（请一定读一下）

- 黑名单只能拦截**已经被报告过的**网站，刚出现的诈骗网站可能检测不到。
- 诈骗话术检查只能根据常见的说法来判断，**没检测出来不代表安全**。只要对方**要钱、要验证码、叫你别告诉别人**，就请先找身边的人或警察商量。
- 请同时开着浏览器自带的保护，例如 Chrome / Firefox 的 [Google Safe Browsing](https://safebrowsing.google.com/)、Edge 的 Microsoft Defender SmartScreen。

## 常见手法：同城约会（约炮）诈骗

1. 在 Telegram 等软件上，有“平台接待员”主动发消息，推荐“同城妹妹”“支持见面支付”
2. 让你下载“平台 App”，或者叫你交会员费、押金来“登记”
3. 等你付了钱，就说你“操作失误”“信誉分下滑”“账户被锁定”，要你花钱“补信誉分”，还说补满了就能退款或提现
4. 你想提现时，又会冒出“退款专员”“售后出款部门”，说要先付“验证金”、做“二次验证”，或者说金额太大要“分笔”提现
5. 对方会拼命让你放心：“百分之 200 保证”“都是实名制账户”“骗人的平台能开这么久吗”“提不出来你可以报警”
6. 不管付多少，都会有新的理由让你继续付。**一旦对方要你“补信誉分”“解冻”“交审核费”才能退钱，就请马上停止付款，去报警。**

## 觉得可能被骗了

- 先停止付款，保存好聊天记录和转账记录
- 日本：警察相谈专线 **#9110**、消费者热线 **188**（[消费者厅](https://www.caa.go.jp/policies/policy/local_cooperation/local_consumer_administration/hotline/)）；紧急情况拨 **110**
- 中国大陆：全国反诈专线 **96110**；紧急情况拨 **110**
- 当心声称能帮你**“追回被骗的钱”**的人，这往往是第二次诈骗
- 骗子发来的“身份证照片”很多是盗用别人的，不能证明对方是真人

## 一起改进

如果发现没检测出来的诈骗话术，或者被误判的情况，欢迎提 Issue 或 Pull Request。
提供诈骗消息作为例子时，请先删掉**名字、电话、账号等个人信息**。

## 测试

```sh
python3 -m unittest discover -s tests -v
node tests/test_web.js
```

## 许可证

[GPL-3.0](LICENSE)。二维码识别使用了 [jsQR](https://github.com/cozmo/jsQR)（Apache-2.0，见 [`docs/vendor/jsQR-LICENSE.txt`](docs/vendor/jsQR-LICENSE.txt)）。
