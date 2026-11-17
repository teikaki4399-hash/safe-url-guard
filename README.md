# safe-url-guard

**English** | [简体中文](README.zh-CN.md)

Free tools that protect you from **malware sites, phishing sites and scam messages**.

> Built so that nobody else has to go through being scammed. Focused on **dating / hookup scams, investment scams, task / job scams and romance scams**.

| Tool | For | What it does |
|---|---|---|
| 🛡 [Whole-computer blocking](#-whole-computer-blocking-every-browser-and-app) | Computers (recommended) | Edits the system hosts file so **every browser and every app** is blocked from dangerous sites; updates daily |
| 🧩 [Browser extension](#-browser-extension-recommended) | Computers (recommended) | Runs when the browser starts and **blocks dangerous sites, even when you click a link** |
| 📱 [Phones](#-on-your-phone) | Phones | Web checker + the phone's own protection settings |
| 🌐 [Web checker](#-web-checker) | Everyone | Check **suspicious messages, links and QR codes** in your browser |
| 🐍 [Python command-line tools](#-python-command-line-tools) | Terminal users | The same checks, scriptable |

All tools are available in **English and Simplified Chinese (简体中文)**. See [Language](#language).

---

## 🛡 Whole-computer blocking (every browser and app)

Writes the blocklists into the system hosts file, so Chrome, Edge, Firefox, Safari and every other app cannot reach listed sites. Updated automatically at startup and once a day.

**Before you start:** install Python 3 (on Windows, from [python.org](https://www.python.org/downloads/); tick "Add python.exe to PATH"). Then download this repository (**Code → Download ZIP**) and unzip it.

**Windows:** search for "PowerShell" in the Start menu, right-click it, choose **Run as administrator**, then run:

```powershell
cd path\to\safe-url-guard-main
python hosts_guard.py install
```

**macOS:** first move the folder to `/Users/Shared/`. macOS stops background jobs from reading Downloads, Desktop and Documents, so daily updates would fail there.

```sh
mv ~/Downloads/safe-url-guard-main /Users/Shared/safe-url-guard
cd /Users/Shared/safe-url-guard
sudo python3 hosts_guard.py install
```

If you installed Python from python.org and see `CERTIFICATE_VERIFY_FAILED`, double-click **Install Certificates.command** in "Applications → Python 3.x" and run the command again.

**Linux:**

```sh
cd path/to/safe-url-guard-main
sudo python3 hosts_guard.py install
```

- Status: `python hosts_guard.py status`
- Uninstall: `python hosts_guard.py uninstall` (as administrator on Windows, with `sudo` on macOS / Linux). The original hosts file is backed up as `hosts.safe-url-guard.bak` before the first change.
- **Do not move or delete the folder after installing**: the daily update runs from it.
- A browser with "secure DNS / DNS over HTTPS" turned on may bypass the hosts file, so **also install the browser extension below**.

## 🧩 Browser extension (recommended)

- Runs automatically when the browser starts and updates the blocklists every 24 hours
- Opening a listed site (or any of its subdomains) shows a warning page instead. **There is no "continue anyway" button.**
- You can add your own sites to block; if a safe site is blocked by mistake, allow it in the settings

### Install (Chrome / Edge)

1. Download this repository: **Code → Download ZIP**, then unzip it
2. Open `chrome://extensions` (Edge: `edge://extensions`)
3. Turn on **Developer mode** (top right)
4. Click **Load unpacked** and choose the `extension` folder
5. Click the 🛡 icon in the toolbar: if it says "Blocking … dangerous sites", it works

> The browser will say the extension can access all sites. This is required to **redirect dangerous sites to the warning page** ([Chrome documentation](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)). The extension does not read page contents and does not send your browsing history anywhere; all of its code is in this repository.

Firefox 128+: open `about:debugging#/runtime/this-firefox`, click "Load Temporary Add-on…" and choose `extension/manifest.json`. This is removed when Firefox restarts; permanent use requires signing through [addons.mozilla.org](https://addons.mozilla.org/). So far it has only been tested on Chromium.

## 🌐 Web checker

**https://teikaki4399-hash.github.io/safe-url-guard/**

- **Message:** paste an SMS, LINE message, e-mail or DM and check it for common scam phrases
- **Link:** check for suspicious traits (look-alike domains, raw IP addresses, …) and how long ago the domain was registered
- **QR code:** read the link inside a QR-code image and check it before opening

Messages and images are checked only in your browser and are never uploaded.

## 📱 On your phone

Phones cannot run this blocker the way computers can (Safari extensions on iPhone must be distributed through the App Store). Combine these instead:

1. **Add the web checker to your home screen:** open https://teikaki4399-hash.github.io/safe-url-guard/ on your phone
   - iPhone (Safari): Share button → **Add to Home Screen**
   - Android (Chrome): ⋮ → **Add to Home screen**

   When you get a suspicious message, link or QR code, **paste it in and check it first**. For a QR code, take a screenshot and choose it in the "QR code" tab.
2. **Turn on the phone's own protection:**
   - iPhone: Settings → Safari → turn on **"Fraudulent Website Warning"** (on newer iOS: Settings → Apps → Safari)
   - Android (Chrome): ⋮ → Settings → Privacy and security → Safe Browsing → **Enhanced protection**
3. **Use a DNS service that blocks malicious domains (covers the whole phone):** for example the non-profit [Quad9](https://quad9.net/), which blocks known malicious domains.
   - Android 9+: Settings → Network & internet → **Private DNS** → "Private DNS provider hostname" → `dns.quad9.net` (menu names vary by phone)
   - iPhone: requires a configuration profile; follow the instructions on Quad9's website

## 🐍 Python command-line tools

Python 3.8+, standard library only. The QR-code checker also needs OpenCV.

```sh
git clone https://github.com/teikaki4399-hash/safe-url-guard.git
cd safe-url-guard

# Link check (download the blocklists first; once a day is a good idea)
python3 safe_url_guard.py update
python3 safe_url_guard.py check https://example.com
python3 safe_url_guard.py open https://example.com     # blocks dangerous sites, asks before suspicious ones
python3 safe_url_guard.py hosts > blocklist-hosts.txt  # blocklist in hosts-file format

# Scam-message check
python3 scam_check.py "Darling, this platform is guaranteed profit, just top up a little first"
python3 scam_check.py -f message.txt --online           # --online: also look up when linked domains were registered

# Domain registration date
python3 domain_age.py https://shop.example.com

# QR code
pip install opencv-python-headless
python3 qr_check.py qr.png
```

Custom lists live in `~/.cache/safe_url_guard/`: `allowlist.txt` and `denylist.txt`, one domain per line.

## Language

| Tool | How to switch |
|---|---|
| Python tools | `python3 safe_url_guard.py lang zh` (or `lang en`). Saved in a `.lang` file next to the scripts. You can also set `SAFE_URL_GUARD_LANG=zh`. A Chinese system locale selects Chinese automatically. |
| Browser extension | Follows the browser's language; change it under the extension's **Settings → Language** |
| Web checker | **English / 中文** buttons at the top right (remembered), or add `?lang=zh` to the URL |

## How it decides

| Check | Source |
|---|---|
| Phishing sites | [OpenPhish](https://openphish.com/phishing_feeds.html) public blocklist (Community Feed) |
| Confirmed scam sites | [`extension/builtin_blocklist.txt`](extension/builtin_blocklist.txt), maintained in this repository |
| Domain age | [RDAP](https://www.icann.org/rdap) (RFC 9082/9083); the server is found through the [IANA bootstrap file](https://data.iana.org/rdap/dns.json). Under 30 days is "very suspicious", under 180 days is "be careful" |
| Scam phrases | Rules in [`docs/scam_rules.json`](docs/scam_rules.json) (Chinese, Japanese and English phrases). Each warning sign adds points, and dangerous combinations such as "romance + money" or "job + prepay" add extra points |

## Limitations (please read)

- Blocklists only cover sites that **have already been reported**; brand-new scam sites may not be caught.
- The message check only knows common phrases. **Not being flagged does not mean it is safe.** If someone **asks for money or a verification code, or tells you not to tell anyone**, talk to someone you trust or the police first.
- Keep your browser's own protection on too, e.g. [Google Safe Browsing](https://safebrowsing.google.com/) in Chrome / Firefox or Microsoft Defender SmartScreen in Edge.

## A common pattern: the dating / hookup "credit score" scam

1. A "platform receptionist" messages you on Telegram or similar, offering "local girls" and "pay when you meet"
2. You are told to download the "platform app" or pay a membership fee or deposit to "register"
3. After you pay, they say you made an "operation error", your "credit score" dropped or your account is "locked", and you must pay to "restore your score" before you can get a refund or withdraw
4. To win your trust they first take a small "verification deposit" (e.g. 300) and let a small amount actually reach you (e.g. 600). **This is bait for the much larger payments that follow.**
5. When you try to withdraw, a "refund specialist" or "payout department" appears and asks for a "verification deposit", a "second verification", or says the amount must be "split"
6. They reassure you constantly: "200% guaranteed", "all accounts are real-name verified", "would a scam platform run this long?", "call the police if you can't withdraw", "a platform this big wouldn't ruin its name over a few thousand"
7. Whatever you pay, there is always another reason to pay again. **Once someone says you must pay to "restore your score", "unfreeze" or "pass review" before you get your money back, stop paying and go to the police.**

## If you think you have been scammed

- Stop paying. Keep all chats and payment records.
- Japan: police consultation **#9110**, consumer hotline **188** ([Consumer Affairs Agency](https://www.caa.go.jp/policies/policy/local_cooperation/local_consumer_administration/hotline/)); emergency **110**
- Mainland China: anti-fraud hotline **96110**; emergency **110**
- Elsewhere: contact your local police and your bank as soon as possible
- Beware of anyone who offers to **"recover your lost money"**: that is often a second scam
- "ID card photos" sent by scammers are often stolen from real people and prove nothing

## Contributing

Missed scam phrases or false alarms? Issues and pull requests are welcome.
When sharing a scam message as an example, please remove **names, phone numbers, account numbers and other personal information** first.

## Tests

```sh
python3 -m unittest discover -s tests -v
node tests/test_web.js
```

## License

[GPL-3.0](LICENSE). QR decoding uses [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0, see [`docs/vendor/jsQR-LICENSE.txt`](docs/vendor/jsQR-LICENSE.txt)).

## Maintenance

A [weekly health check](.github/workflows/health.yml) runs all tests and downloads every blocklist feed, so a feed that moves or shuts down is noticed quickly. You can also run it by hand from the **Actions** tab.
