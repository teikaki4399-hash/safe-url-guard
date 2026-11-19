// Tests for the web core logic (docs/scam_core.js), checking it gives the same scores as the Python version.
// Run: node tests/test_web.js
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
} catch (e) { console.log("(python3 not found; skipping comparison with the Python version)"); }

samples.forEach((s, i) => {
  const r = Core.analyze(s.text, rules);
  assert(r.level >= s.min && r.level <= s.max, `unexpected level: ${s.text} -> ${r.level}`);
  if (pyScores) assert.strictEqual(r.score, pyScores[i], `score differs from the Python version: ${s.text}`);
});

const h = (u) => Core.urlHeuristics(u).warnings.length;
assert.strictEqual(h("https://www.python.org/"), 0);
assert(h("http://192.168.0.1/login") >= 2);
assert(h("https://аpple.com") >= 1, "Cyrillic look-alike domain should be flagged");
assert(h("https://google.com@bad.io") >= 1);
assert.strictEqual(Core.urlHeuristics("https://www.Example.com/x").host, "example.com");

const bs = { services: [[["com"], ["https://rdap.example/"]], [["co.uk", "uk"], ["https://uk.example/"]]] };
assert.strictEqual(Core.rdapBase("a.b.com", bs), "https://rdap.example/");
assert.deepStrictEqual(Core.candidates("a.example.com"), ["example.com", "a.example.com"]);
assert.strictEqual(Core.verdictForDays(5), "DANGER");
assert.strictEqual(Core.verdictForDays(100), "WARN");
assert.strictEqual(Core.verdictForDays(1000), "OK");
// extension/rdap.js (new-domain warning bar) must agree with the web version
const Rdap = require(path.join(root, "extension", "rdap.js"));
assert.strictEqual(Rdap.rdapBase("a.b.com", bs), Core.rdapBase("a.b.com", bs));
assert.strictEqual(Rdap.rdapBase("x.example.co.uk", bs), "https://uk.example/");
assert.deepStrictEqual(Rdap.candidates("a.example.com"), Core.candidates("a.example.com"));
assert(!Rdap.lookupable("192.168.0.1") && !Rdap.lookupable("localhost") && Rdap.lookupable("shop.example.com"));
(async () => {
  const fake = url => {
    if (url === "https://rdap.example/domain/example.com") {
      return Promise.resolve({ events: [{ eventAction: "registration", eventDate: "2026-11-10T00:00:00Z" }] });
    }
    const e = new Error("HTTP 404"); e.status = 404; return Promise.reject(e);
  };
  const r = await Rdap.lookup("shop.example.com", bs, fake);
  assert.strictEqual(r.domain, "example.com");
  assert.strictEqual(Rdap.ageDays(r.registered, Date.parse("2026-11-17T00:00:00Z")), 7);
  assert.strictEqual((await Rdap.lookup("x.jp", bs, fake)).reason, "no_rdap");
  assert.strictEqual((await Rdap.lookup("nope.com", bs, fake)).reason, "not_found");
})().catch(e => { console.error(e); process.exit(1); });

// every UI language has exactly the same message keys as English (web checker and extension)
function loadI18N(file, globals) {
  const src = fs.readFileSync(path.join(root, file), "utf8").replace(/\}\)\(this\);\s*$/, "})(root);");
  const names = Object.keys(globals);
  const r = {};
  new Function("root", ...names, src)(r, ...names.map(n => globals[n]));
  return r.I18N;
}
const dom = { documentElement: {}, querySelectorAll: () => [] };
const i18nFiles = {
  "docs/i18n.js": loadI18N("docs/i18n.js", { document: dom, location: { search: "" }, localStorage: { getItem: () => null }, navigator: { language: "ja-JP" } }),
  "extension/i18n.js": loadI18N("extension/i18n.js", { chrome: { i18n: { getUILanguage: () => "ja" } }, navigator: {} })
};
for (const [file, I] of Object.entries(i18nFiles)) {
  assert.strictEqual(I.lang, "ja", `${file}: a Japanese browser should get the Japanese UI`);
  const en = Object.keys(I.messages.en).sort();
  for (const lang of ["zh", "ja"]) assert.deepStrictEqual(Object.keys(I.messages[lang]).sort(), en, `${file}: ${lang} keys differ from en`);
}
// rule texts exist in all three languages
const LANGS = ["en", "ja", "zh"];
const keysOf = v => Object.keys(v).sort();
Object.values(rules.categories).forEach(v => assert.deepStrictEqual(keysOf(v), LANGS));
rules.rules.forEach(r => assert.deepStrictEqual(keysOf(r.reason), LANGS, r.id));
rules.combos.forEach(c => assert.deepStrictEqual(keysOf(c.reason), LANGS));
assert.deepStrictEqual(keysOf(rules.advice), LANGS);

console.log(`OK (${samples.length} samples${pyScores ? ", identical to the Python version" : ""})`);
