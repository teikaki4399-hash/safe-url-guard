// 网页版核心逻辑 (docs/scam_core.js) 的测试，并确认结果与 Python 版一致。
// 运行: node tests/test_web.js
"use strict";
const fs = require("fs");
const path = require("path");
const assert = require("assert");
const { execFileSync } = require("child_process");
const root = path.join(__dirname, "..");
const Core = require(path.join(root, "docs", "scam_core.js"));
const rules = Core.compile(JSON.parse(fs.readFileSync(path.join(root, "docs", "scam_rules.json"), "utf8")));
const samples = JSON.parse(fs.readFileSync(path.join(__dirname, "samples.json"), "utf8")).samples;

let pyScores = null;
try {
  const code = "import json,sys;sys.path.insert(0,'.');import scam_check as s;R=s.load_rules();" +
    "print(json.dumps([s.analyze(t,R)['score'] for t in json.load(sys.stdin)]))";
  pyScores = JSON.parse(execFileSync("python3", ["-c", code], { cwd: root, input: JSON.stringify(samples.map(s => s.text)) }));
} catch (e) { console.log("（未找到 python3，跳过与 Python 版的对比）"); }

samples.forEach((s, i) => {
  const r = Core.analyze(s.text, rules);
  assert(r.level >= s.min && r.level <= s.max, `等级不符: ${s.text} -> ${r.level}`);
  if (pyScores) assert.strictEqual(r.score, pyScores[i], `与 Python 版分数不一致: ${s.text}`);
});

const h = (u) => Core.urlHeuristics(u).warnings.length;
assert.strictEqual(h("https://www.python.org/"), 0);
assert(h("http://192.168.0.1/login") >= 2);
assert(h("https://аpple.com") >= 1, "西里尔字母仿冒域名应被检测");
assert(h("https://google.com@bad.io") >= 1);
assert.strictEqual(Core.urlHeuristics("https://www.Example.com/x").host, "example.com");

const bs = { services: [[["com"], ["https://rdap.example/"]], [["co.uk", "uk"], ["https://uk.example/"]]] };
assert.strictEqual(Core.rdapBase("a.b.com", bs), "https://rdap.example/");
assert.deepStrictEqual(Core.candidates("a.example.com"), ["example.com", "a.example.com"]);
assert.strictEqual(Core.verdictForDays(5), "DANGER");
assert.strictEqual(Core.verdictForDays(100), "WARN");
assert.strictEqual(Core.verdictForDays(1000), "OK");
console.log(`OK (${samples.length} 条样本${pyScores ? "，与 Python 版一致" : ""})`);
