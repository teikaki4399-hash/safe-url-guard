# safe-url-guard

[English](README.md) | **简体中文**

防止被**病毒网站、钓鱼网站和诈骗消息**骗到的一组免费工具。

| 工具 | 适合谁 | 能做什么 |
|---|---|---|
| 🛡 [整台电脑拦截](#-整台电脑拦截所有浏览器和-app) | 电脑（推荐） | 修改系统 hosts，**所有浏览器、所有 App** 都打不开危险网站，每天自动更新 |
| 🧩 [浏览器扩展](#-浏览器扩展推荐) | 电脑（推荐） | 浏览器启动后自动运行，**访问危险网站时直接拦截**，点链接也会被挡住 |
| 📱 [手机](#-手机怎么用) | 手机 | 网页版检查 + 手机自带的防护设置 |
| 🌐 [网页版检查工具](#-网页版检查工具) | 不会编程的人 | 打开网页，检查**可疑消息、网址、二维码** |
| 🐍 [Python 命令行工具](#-python-命令行工具) | 会用终端的人 | 和上面相同的检查，可以写进脚本里 |

所有工具都支持**英文和简体中文**，切换方法见[语言设置](#语言设置)。

---

## 🛡 整台电脑拦截（所有浏览器和 App）

把黑名单写进系统的 hosts 文件。Chrome、Edge、Firefox、Safari 以及其他 App 都会连不上黑名单上的网站。开机时和每天各自动更新一次。

**准备：** 先安装 Python 3（Windows 可以从 [python.org](https://www.python.org/downloads/) 下载，安装时勾选 “Add python.exe to PATH”）。然后下载这个仓库（**Code → Download ZIP**），解压。

**Windows：** 在开始菜单搜索 “PowerShell”，右键选 **以管理员身份运行**，再执行：

```powershell
cd 解压后的文件夹路径\safe-url-guard-main
python hosts_guard.py install
```

**macOS：** 先把解压后的文件夹移到 `/Users/Shared/`。macOS 会限制后台程序读取“下载”“桌面”“文稿”文件夹，放在那里会导致每日自动更新失败。

```sh
mv ~/Downloads/safe-url-guard-main /Users/Shared/safe-url-guard
cd /Users/Shared/safe-url-guard
sudo python3 hosts_guard.py install
```

如果 Python 是从 python.org 安装的，出现 `CERTIFICATE_VERIFY_FAILED` 时，请先双击“应用程序 → Python 3.x”文件夹里的 **Install Certificates.command**，然后再运行一次。

**Linux：**

```sh
cd 解压后的文件夹路径/safe-url-guard-main
sudo python3 hosts_guard.py install
```

- 查看状态：`python hosts_guard.py status`
- 卸载：`python hosts_guard.py uninstall`（Windows 用管理员身份运行，macOS / Linux 前面加 `sudo`）。第一次修改前的 hosts 会备份为 `hosts.safe-url-guard.bak`
- 安装后**不要移动或删除这个文件夹**，自动更新要用到里面的文件
- 如果浏览器开了“安全 DNS / DNS over HTTPS”，可能会绕过 hosts 文件。所以最好**同时安装下面的浏览器扩展**

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

目前还不支持 Firefox（扩展使用的是 Chrome 方式的后台程序）。用 Firefox 的话，请用上面的[整台电脑拦截](#-整台电脑拦截所有浏览器和-app)。

## 🌐 网页版检查工具

网址：**https://teikaki4399-hash.github.io/safe-url-guard/?lang=zh**

- **消息检查**：粘贴短信、LINE、邮件、私信内容，检查里面有没有常见的诈骗话术
- **网址检查**：检查可疑特征（仿冒域名、IP 地址等），并查询域名注册了多久
- **二维码检查**：读取二维码图片里的网址，检查之后再决定要不要打开

消息和图片只在浏览器里检查，不会上传到服务器。

## 📱 手机怎么用

手机上没法像电脑那样装这个拦截程序（iPhone 的 Safari 扩展必须通过 App Store 发布）。可以组合使用下面几种方法：

1. **把网页版加到主屏幕：** 用手机浏览器打开 https://teikaki4399-hash.github.io/safe-url-guard/?lang=zh
   - iPhone（Safari）：点分享按钮 → **添加到主屏幕**
   - Android（Chrome）：点右上角 ⋮ → **添加到主屏幕**

   收到可疑的消息、链接或二维码时，先**复制粘贴到这里检查**。二维码可以先截图，再在“二维码检查”里选这张截图。
2. **打开手机自带的防护：**
   - iPhone：设置 → Safari → 打开 **“欺诈性网站警告”**（较新的 iOS 版本在 设置 → App → Safari 里）
   - Android（Chrome）：⋮ → 设置 → 隐私和安全 → 安全浏览 → **增强型保护**
3. **使用会拦截恶意网站的 DNS（整台手机都有效）：** 例如非营利组织 [Quad9](https://quad9.net/)，它会拦截已知的恶意域名。
   - Android 9 及以上：设置 → 网络和互联网 → **私人 DNS** → 选“私人 DNS 提供商主机名”，输入 `dns.quad9.net`（不同手机的菜单名称可能略有不同）
   - iPhone：需要安装配置描述文件，请按 Quad9 官网的说明操作

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

## 语言设置

| 工具 | 切换方法 |
|---|---|
| Python 工具 | `python3 safe_url_guard.py lang zh`（改回英文用 `lang en`）。设置会保存在脚本旁边的 `.lang` 文件里；也可以设置环境变量 `SAFE_URL_GUARD_LANG=zh`。系统语言是中文时会自动显示中文 |
| 浏览器扩展 | 默认跟随浏览器的语言；可以在扩展的 **设置 → 语言** 里切换 |
| 网页版 | 右上角的 **English / 中文** 按钮（会记住选择），或者在网址后面加 `?lang=zh` |

## 判断依据

| 检查内容 | 依据 |
|---|---|
| 钓鱼网站 | [OpenPhish](https://openphish.com/phishing_feeds.html) 的公开黑名单（Community Feed） |
| 已确认的诈骗网站 | 本仓库维护的 [`extension/builtin_blocklist.txt`](extension/builtin_blocklist.txt) |
| 域名注册时间 | [RDAP](https://www.icann.org/rdap)（RFC 9082/9083），通过 [IANA bootstrap](https://data.iana.org/rdap/dns.json) 找到对应的查询服务器。注册不到 30 天判为“非常可疑”，不到 180 天判为“请小心” |
| 诈骗话术 | [`docs/scam_rules.json`](docs/scam_rules.json) 里的规则（覆盖中文、日文、英文的说法），按特征打分，并对危险的组合额外加分，例如“感情 + 要钱”“兼职 + 先垫付” |

## 局限性（请一定读一下）

- 黑名单只能拦截**已经被报告过的**网站，刚出现的诈骗网站可能检测不到。
- 诈骗话术检查只能根据常见的说法来判断，**没检测出来不代表安全**。只要对方**要钱、要验证码、叫你别告诉别人**，就请先找身边的人或警察商量。
- 请同时开着浏览器自带的保护，例如 Chrome / Firefox 的 [Google Safe Browsing](https://safebrowsing.google.com/)、Edge 的 Microsoft Defender SmartScreen。

## 常见手法：“信誉分 / 退款”诈骗

1. 在 Telegram 等软件上，有自称“平台接待员”的人主动发消息，介绍某个交友平台
2. 让你下载“平台 App”，或者叫你交会员费、押金来“登记”
3. 等你付了钱，就说你“操作失误”“信誉分下滑”“账户被锁定”，要你花钱“补信誉分”，还说补满了就能退款或提现
4. 为了让你相信，对方会先让你付一小笔“验证金”（比如 300 元），再让一小笔钱真的到账（比如 600 元）。**这是诱饵，是为了骗你接下来付更大的金额。**
5. 你想提现时，又会冒出“退款专员”“售后出款部门”，说要先付“验证金”、做“二次验证”，或者说金额太大要“分笔”提现
6. 对方会拼命让你放心：“百分之 200 保证”“都是实名制账户”“骗人的平台能开这么久吗”“提不出来你可以报警”“这么大的平台不至于为了几千块砸招牌”
7. 不管付多少，都会有新的理由让你继续付。**一旦对方要你“补信誉分”“解冻”“交审核费”才能退钱，就请马上停止付款，去报警。**

## 骗子常用的心理手段

诈骗是按照人的心理设计出来的。官方提醒和公安通报里，反复出现的是这几种手段：

| 手段 | 具体表现 |
|---|---|
| **恐惧** | “账户要被冻结”“你涉嫌犯罪”“你操作失误了” |
| **贪心 / 侥幸** | 先让你小赚一笔，或者让一小笔提现真的到账，用来引你付更多的钱 |
| **制造从众** | 群里人人晒收益截图。公安通报的一个案例里，54 人的“兼职群”中有 53 人是骗子（[光明网](https://m.gmw.cn/2026-08/24/content_1304553152.htm)） |
| **稀缺 / 催促** | “名额只剩 3 个”“30 分钟内完成”，不停地发消息催你 |
| **“把亏的钱赚回来”** | 以“解冻”“提现”为由让你继续付钱；之后又有人说“能帮你追回损失”，要你先交费（二次诈骗） |
| **不起眼的小字** | 要付的金额或必须备注的“代码”用很小、很淡的字写着，事后说你操作错了 |
| **他们自己的 App 或聊天窗口** | 通过链接安装的 App、网页上自动弹出的聊天窗口。假 App 能显示假余额，甚至控制你的手机 |
| **让你孤立无援** | “不要告诉家人和银行”，把你拉进 Telegram 或私密群 |

资料来源：日本警察厅关于 SNS 型投资诈骗、恋爱诈骗的统计（[npa.go.jp](https://www.npa.go.jp/bureau/safetylife/sos47/new-topics/260420/01.html)）、FBI IC3 关于虚拟货币投资诈骗的警告（[ic3.gov](https://www.ic3.gov/PSA/2022/psa221003)）、新华社关于屏幕共享和假 App 诈骗的报道（[新华网](https://www.news.cn/legal/20250423/149dfe212a0b49efb6937d582e058bb8/c.html)）。

## 觉得可能被骗了

- 先停止付款，保存好聊天记录和转账记录
- 日本：警察相谈专线 **#9110**、消费者热线 **188**（[消费者厅](https://www.caa.go.jp/policies/policy/local_cooperation/local_consumer_administration/hotline/)）；紧急情况拨 **110**
- 中国大陆：全国反诈专线 **96110**；紧急情况拨 **110**
- 其他国家和地区：尽快联系当地警察和你的银行
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

## 维护

[每周自动体检](.github/workflows/health.yml)会跑一遍全部测试，并下载所有黑名单。如果某个黑名单的地址变了或停用了，能很快发现。也可以在仓库的 **Actions** 页面手动运行。
