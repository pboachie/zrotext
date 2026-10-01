// SPDX-License-Identifier: AGPL-3.0-only
// Real Chromium QA with an explicit in-memory fixture adapter, never owner credentials.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const http = require("node:http");
const args = process.argv.slice(2);
function option(name) { const at = args.indexOf(name); return at < 0 ? undefined : args[at + 1]; }
const { chromium } = require(require.resolve("playwright", {paths:[option("--tools") || process.cwd()]}));
const root = path.resolve(__dirname, "../web/owner");
const files = new Set(["conversation.html","conversation-core.js","conversation.js","conversation.css","devices.css"]);
const mime = {".html":"text/html", ".js":"text/javascript", ".css":"text/css"};
const server = http.createServer(async(req,res)=>{
  const filename = new URL(req.url,"http://localhost").pathname.slice(1);
  if (!files.has(filename)) {res.writeHead(404);res.end();return;}
  res.writeHead(200,{"Content-Type":mime[path.extname(filename)],"Cache-Control":"no-store"});res.end(await fs.readFile(path.join(root,filename)));
});
async function fixture() {
  const uuid=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,"0")).join("").replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/,"$1-$2-$3-$4-$5");
  window.fixtureCalls = {prepare:0,send:0}; window.fixtureDuration = 60000;
  const scope = {account:uuid(),session:uuid(),interval:uuid(),device:uuid(),line:uuid(),generation:"1",peer:"+12",reader:"fixture",manifest:"fixture"};
  let close;
  window.ZtConversationSimulatorAdapter = {initialEvent:uuid(),
    authority:async()=>({scope,phase:"active",validForMs:window.fixtureDuration}),
    read:async()=>"Synthetic phone content <script>literal</script> Ω",
    prepare:async({body})=>{window.fixtureCalls.prepare++;return {confirm:async(guard)=>{await new Promise(r=>setTimeout(r,100));guard();window.fixtureCalls.send++;return {status:"simulator_accepted"};}};},
    onClose(fn){close=fn;},
  };
  window.closeFixture=()=>close();
}
(async()=>{
  await new Promise(resolve=>server.listen(0,"localhost",resolve));
  const origin=`http://localhost:${server.address().port}`;
  const browser=await chromium.launch({headless:true,executablePath:option("--browser")});
  let checks=0;
  try {
    for (const viewport of [{width:1100,height:850},{width:360,height:920}]) {
      const context=await browser.newContext({viewport,reducedMotion:"reduce"});
      await context.route("**/*",route=>route.request().url().startsWith(origin+"/")?route.continue():route.abort());
      await context.addInitScript(fixture);
      const page=await context.newPage();const errors=[];page.on("pageerror",e=>errors.push(e.message));
      await page.goto(origin+"/conversation.html");
      await page.getByRole("button",{name:"Check conversation authorization"}).click();
      await page.locator("#body").waitFor({state:"visible"});
      assert.equal(await page.locator("#messages").textContent(),"Phone received: Synthetic phone content <script>literal</script> Ω");
      const text="Synthetic exact reply Ω\nTrailing spaces  ";await page.locator("#body").fill(text);
      await page.getByRole("button",{name:"Review message",exact:true}).click();
      assert.equal(await page.locator("#review-body").textContent(),text);
      assert.equal(await page.evaluate(()=>fixtureCalls.send),0);
      await page.locator("#body").fill("Changed");assert.equal(await page.locator("#confirmation").isVisible(),false);
      await page.locator("#body").fill(text);await page.getByRole("button",{name:"Review message",exact:true}).click();
      await page.getByRole("button",{name:"Cancel review"}).press("Enter");assert.equal(await page.locator("#body").inputValue(),text);
      await page.getByRole("button",{name:"Review message",exact:true}).click();
      await page.getByRole("button",{name:"Confirm this send"}).press("Enter");
      await page.waitForFunction(()=>fixtureCalls.send===1);assert.equal(await page.locator("#body").inputValue(),"");
      assert.ok((await page.locator("#messages").textContent()).includes(text));
      if(viewport.width===360)await page.addStyleTag({content:":root {font-size:125%;}"});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,"no horizontal overflow at narrow/large text");
      const artifacts=option("--artifacts");if(artifacts){await fs.mkdir(artifacts,{recursive:true});await page.screenshot({path:path.join(artifacts,`conversation-${viewport.width}.png`),fullPage:true});}
      await page.evaluate(()=>closeFixture());assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").inputValue(),"");
      await page.evaluate(()=>{fixtureDuration=300;});await page.getByRole("button",{name:"Check conversation authorization"}).click();
      await page.locator("#body").fill(text);await page.getByRole("button",{name:"Review message",exact:true}).click();
      await page.waitForTimeout(400);await page.locator("#confirm").evaluate(el=>el.click());
      assert.equal(await page.evaluate(()=>fixtureCalls.send),1);assert.equal(await page.locator("#review-body").textContent(),"");
      assert.deepEqual(errors,[]);assert.equal(await page.evaluate(()=>Object.keys(localStorage).length+Object.keys(sessionStorage).length),0);
      await context.close();checks++;
    }
    const context=await browser.newContext();const page=await context.newPage();await page.goto(origin+"/conversation.html");
    assert.equal(await page.locator("#connect").isDisabled(),true);await context.close();checks++;
    process.stdout.write(`PASS ${checks} real Chromium contexts: desktop, narrow/large text, inert page; exact review, keyboard confirmation, close/expiry and no storage\n`);
  } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{server.close();process.stderr.write(error.stack+"\n");process.exitCode=1;});
