# safe-url-guard

打开网站**之前**先检查 URL，避免访问病毒（恶意软件）/ 诈骗（钓鱼）网站的小工具。
只用到 Python 标准库，无需安装额外的包（Python 3.8+）。

## 原理

1. **公开黑名单比对**（检查域名及其所有上级域名）
   - [URLhaus](https://urlhaus.abuse.ch/)（abuse.ch）— 正在分发恶意软件的网站
   - [OpenPhish Community Feed](https://openphish.com/phishing_feeds.html) — 钓鱼网站
2. **启发式检查**（只作提醒，不代表一定有害）：未使用 HTTPS、直接用 IP 地址、punycode（`xn--`）仿冒域名、URL 中含 `@`、子域名层级过多、非标准端口等

## 使用方法

```sh
git clone https://github.com/teikaki4399-hash/safe-url-guard.git
cd safe-url-guard

# 1. 下载黑名单（建议每天运行一次）
python3 safe_url_guard.py update

# 2. 检查 URL（退出码: 0=安全 1=注意 2=危险）
python3 safe_url_guard.py check https://example.com http://1.2.3.4/login

# 3. 检查后再打开：危险的会被拦截，可疑的会先询问
python3 safe_url_guard.py open https://example.com

# 4. 生成 hosts 格式的拦截列表（可在整台电脑上拦截）
python3 safe_url_guard.py hosts > blocklist-hosts.txt
```

### 白名单 / 自定义黑名单

在 `~/.cache/safe_url_guard/` 下创建以下文件，每行一个域名：

- `allowlist.txt` — 始终视为安全
- `denylist.txt` — 始终拦截

## 注意事项

- 黑名单只能拦截**已知的**恶意网站，刚出现的新网站可能检测不到。显示 “安全?” 也不能保证 100% 安全。
- 把 `hosts` 的输出追加到系统 hosts 文件（Linux/macOS: `/etc/hosts`，Windows: `C:\Windows\System32\drivers\etc\hosts`）需要管理员权限，修改前请先备份。
- 要获得更全面的保护，建议同时使用浏览器自带的保护功能，例如 [Google Safe Browsing](https://safebrowsing.google.com/)（Chrome / Firefox 默认开启）和 Microsoft Defender SmartScreen（Edge）。

## 测试

```sh
python3 -m unittest -v
```
