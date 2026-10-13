// Run with Node's test runner and Playwright on the module path; see README.md.
// A Kimi Code membership: the add sheet lists Kimi Code and Kimi Code (China)
// under Subscriptions with Kimi's logo; there is no risk step (Kimi lets
// members use third-party tools), so a click starts the sign-in at once,
// asking for {agent:"kimi-code-plan"}, and the box shows Kimi's message with
// the device code, not GitHub's. English and Chinese; no backend, the API is
// faked here.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { test } = require("node:test");
const { chromium, webkit } = require("playwright");

const assets = path.resolve(__dirname, "../assets");

function server(lang, asked) {
  return async (route) => {
    const url = new URL(route.request().url());
    const json = (data) => route.fulfill({ json: data });
    if (url.pathname === "/boot.js") return route.fulfill({ contentType: "text/javascript", body: `window.bootPrefs = {lang:"${lang}",theme:"light",web:false};` });
    if (url.pathname === "/wails/runtime.js") return route.fulfill({ contentType: "text/javascript", body: "export const Window = {};" });
    if (url.pathname === "/api/state") return json({ agents: [], profiles: [], settings: { lang, theme: "light" } });
    if (url.pathname === "/api/providers") return json({ providers: [{ id: "openai", name: "OpenAI", icon: "openai", preset: "openai", models: [], agents: [], key: { set: true, masked: "sk-…ab12" } }], presets: [], excluded: [], gateway: { running: true, window: true } });
    if (url.pathname === "/api/groups") return json({ groups: [], pools: [] });
    if (url.pathname === "/api/gateway/trace") return json({ routes: [] });
    if (url.pathname === "/api/signin") {
      asked.push(route.request().postDataJSON());
      return json({ id: "s1", agent: "kimi-code-plan", state: "waiting", url: "https://www.kimi.ai/code/device?user_code=KIMI-42", code: "KIMI-42" });
    }
    if (url.pathname.startsWith("/api/signin/")) return json({ id: "s1", agent: "kimi-code-plan", state: "waiting", url: "https://www.kimi.ai/code/device?user_code=KIMI-42", code: "KIMI-42" });
    if (url.pathname.startsWith("/api/")) return json({});
    const file = path.join(assets, url.pathname === "/" ? "index.html" : url.pathname);
    const contentType = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" }[path.extname(file)];
    try { await route.fulfill({ body: await fs.readFile(file), contentType }); } catch { await route.fulfill({ status: 404, body: "" }); }
  };
}

const L = {
  en: { msg: "magpie opened Kimi's sign-in page. Enter this code there; the account shows up here as soon as you're done.", plan: "Kimi Code Allegro" },
  zh: { msg: "已打开 Kimi 登录页，请在其中输入下方验证码；完成后账号会出现在这里。", plan: "Kimi Code Allegro" },
  "zh-TW": { msg: "已開啟 Kimi 登入頁，請在其中輸入下方驗證碼；完成後帳號會出現在這裡。", plan: "Kimi Code Allegro" },
  ja: { msg: "magpie が Kimi のサインインページを開きました。そこでこのコードを入力してください。完了するとすぐにアカウントがここに表示されます。", plan: "Kimi Code Allegro" },
  de: { msg: "magpie hat die Anmeldeseite von Kimi geöffnet. Geben Sie dort diesen Code ein; das Konto erscheint hier, sobald Sie fertig sind.", plan: "Kimi Code Allegro" },
};

for (const engine of (process.env.BROWSER ? [process.env.BROWSER] : ["chromium", "webkit"])) {
  test(engine + ": a Kimi Code membership", async (t) => {
    const browser = await (engine === "webkit" ? webkit.launch() : chromium.launch({ channel: "chromium" }));
    t.after(() => browser.close());
    for (const lang of ["en", "zh", "zh-TW", "ja", "de"]) {
      await t.test(lang, async () => {
        const w = L[lang];
        const page = await (await browser.newContext({ viewport: { width: 900, height: 800 } })).newPage();
        const errors = [], asked = [];
        page.on("pageerror", (e) => errors.push(e.message));
        await page.route("**/*", server(lang, asked));
        await page.goto("http://magpie.test/?view=providers");
        await page.locator("#addProvider").click();
        const sheet = page.locator("#addSheet");
        const row = sheet.locator('.tile[data-pick="Kimi Code"]');
        await row.waitFor();
        assert.match(await row.getAttribute("title"), /Membership/);
        assert.match(await row.getAttribute("title"), /kimi\.ai/);
        // both sites are listed, Kimi's own logo on each
        await sheet.locator('.tile[data-pick="Kimi Code CN"]').waitFor();
        assert.equal(await row.locator(".ic").getAttribute("data-icon"), "kimi");
        const logo = await page.evaluate(async () => { const r = await fetch("icons/kimi.svg"); return [r.status, await r.text()]; });
        assert.equal(logo[0], 200);
        assert.match(logo[1], /<svg/);

        // a signed-in account's plan, in the page's language
        assert.equal(await page.evaluate(() => accountPlan({ agent: "kimi-code-plan", plan: "Allegro" })), w.plan);

        const top = await page.evaluate(() => window.scrollY);
        await row.click();
        const box = sheet.locator(".signing");
        await box.waitFor();
        // no risk step: the sign-in starts at once
        await assert.doesNotReject(async () => { for (let i = 0; i < 50 && !asked.length; i++) await page.waitForTimeout(50); });
        assert.deepEqual(asked, [{ agent: "kimi-code-plan" }]);
        await box.locator(".devcode code").waitFor();
        assert.equal(await box.locator(".devcode code").textContent(), "KIMI-42");
        assert.equal(await box.locator(".s").first().textContent(), w.msg);
        assert.doesNotMatch(await box.textContent(), /GitHub/);
        assert.equal(await page.evaluate(() => window.scrollY), top, "the click scrolls nothing");
        assert.deepEqual(errors, []);
      });
    }
  });
}
