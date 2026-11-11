// Tests packaging/site/worker.js against a bucket held in memory and a fetch
// that answers for Mintlify.
import { strict as assert } from "node:assert";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(new URL("../../packaging/site/worker.js", import.meta.url));
// A data: URL is a module whatever the Node version decides about .js files.
const worker = (await import(`data:text/javascript;base64,${source.toString("base64")}`)).default;

const SITE = "https://filetrace.eorlov.org";

function object(key, data, contentType) {
  return {
    key,
    size: data.length,
    httpEtag: `"etag-${key}"`,
    uploaded: new Date(Date.UTC(2026, 10, 11)),
    writeHttpMetadata(headers) {
      headers.set("content-type", contentType);
    },
    data,
  };
}

// The parts of the R2 binding the Worker uses, with R2's handling of Range and
// If-None-Match.
function bucket(entries, { undefinedBody = false } = {}) {
  const objects = new Map(entries.map(([key, text, type]) => [key, object(key, Buffer.from(text), type)]));
  return {
    keys: [],
    async head(key) {
      this.keys.push(key);
      const o = objects.get(key);
      return o ? { ...o } : null;
    },
    async get(key, options = {}) {
      this.keys.push(key);
      const o = objects.get(key);
      if (!o) return null;
      const result = { ...o };
      // The R2 Workers API reference: a failed precondition returns an R2Object whose body is
      // undefined. Behind the Worker the real bucket answered If-None-Match with 304.
      if (options.onlyIf?.get("if-none-match") === o.httpEtag) {
        if (undefinedBody) result.body = undefined;
        return result;
      }
      const range = options.range?.get("range");
      if (range) {
        const [, from, to] = /^bytes=(\d+)-(\d*)$/.exec(range);
        const offset = Number(from);
        // Observed only, the reference does not say: behind the Worker the real bucket answered
        // "bytes=500-600" of a 21-byte object with 416, which the Worker gives when get() throws.
        if (offset >= o.size) throw new Error("InvalidRange");
        const end = to === "" ? o.size - 1 : Math.min(Number(to), o.size - 1);
        result.range = { offset, length: end - offset + 1 };
        result.body = o.data.subarray(offset, end + 1);
      } else {
        result.body = o.data;
      }
      return result;
    },
  };
}

// fetch as the Worker sees it: every call is recorded and answered by `answer`.
function mintlify(answer) {
  const calls = [];
  globalThis.fetch = async (request, init) => {
    calls.push({ request, init });
    return answer(request);
  };
  return calls;
}

async function call(path, init = {}, entries = [], options = {}) {
  const env = { SITE: bucket(entries, options) };
  const response = await worker.fetch(new Request(`${SITE}${path}`, init), env);
  return { response, env };
}

const INSTALLER = ["install.sh", "#!/bin/sh\necho installed\n", "text/x-shellscript"];

test("a download is served from the bucket", async () => {
  const calls = mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/install.sh", {}, [INSTALLER]);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/x-shellscript");
  assert.equal(response.headers.get("etag"), '"etag-install.sh"');
  assert.equal(response.headers.get("accept-ranges"), "bytes");
  assert.equal(await response.text(), INSTALLER[1]);
  assert.equal(calls.length, 0);
});

test("HEAD gives the length without a body", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/install.sh", { method: "HEAD" }, [INSTALLER]);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-length"), String(INSTALLER[1].length));
  assert.equal(await response.text(), "");
});

test("a missing download is 404 from the bucket", async () => {
  const calls = mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/dist/v26.11.1.147-stable/missing.tar.gz");
  assert.equal(response.status, 404);
  assert.equal(calls.length, 0);
});

test("a range is answered with 206 and Content-Range", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/install.sh", { headers: { range: "bytes=2-5" } }, [INSTALLER]);
  assert.equal(response.status, 206);
  assert.equal(response.headers.get("content-range"), `bytes 2-5/${INSTALLER[1].length}`);
  assert.equal(await response.text(), INSTALLER[1].slice(2, 6));
});

test("a range past the end is 416", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/install.sh", { headers: { range: "bytes=900-" } }, [INSTALLER]);
  assert.equal(response.status, 416);
});

test("a matching If-None-Match is 304", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const headers = { "if-none-match": '"etag-install.sh"' };
  const { response } = await call("/install.sh", { headers }, [INSTALLER]);
  assert.equal(response.status, 304);
  assert.equal(await response.text(), "");
});

test("a failed precondition is 304 when body is present but undefined", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const headers = { "if-none-match": '"etag-install.sh"' };
  const { response } = await call("/install.sh", { headers }, [INSTALLER], { undefinedBody: true });
  assert.equal(response.status, 304);
  assert.equal(await response.text(), "");
});

test("an escaped key is looked up unescaped", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const key = "dist/v26.11.1.80+5.gabc1234/filetrace.tar.gz";
  const { response, env } = await call("/dist/v26.11.1.80%2B5.gabc1234/filetrace.tar.gz", {}, [
    [key, "archive", "application/gzip"],
  ]);
  assert.equal(response.status, 200);
  assert.deepEqual(env.SITE.keys, [key]);
});

test("a download refuses methods other than GET and HEAD", async () => {
  mintlify(() => assert.fail("the docs were asked"));
  const { response } = await call("/install.sh", { method: "POST", body: "x" }, [INSTALLER]);
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
});

test("pages go to Mintlify, downloads never do", async () => {
  const calls = mintlify(() => new Response("<html></html>", { headers: { "content-type": "text/html" } }));
  const pages = ["/", "/installation", "/cli/files", "/_mintlify/assets/app.js", "/install.sh.html",
                 "/gpg.keys", "/aptitude"];
  for (const path of pages) {
    const { env } = await call(path);
    assert.deepEqual(env.SITE.keys, [], path);
  }
  for (const path of ["/apt/dists/stable/InRelease", "/rpm/stable/x86_64/repodata/repomd.xml",
                      "/apk/stable/x86_64/APKINDEX.tar.gz", "/channels/stable", "/versions/26.11.1.147",
                      "/gpg.key"]) {
    const { env } = await call(path);
    assert.equal(env.SITE.keys.length, 1, path);
  }
  assert.deepEqual(calls.map((c) => new URL(c.request.url).pathname), pages);
});

test("the request to Mintlify names the public host", async () => {
  const calls = mintlify(() => new Response("ok", { headers: { "content-type": "text/html" } }));
  await call("/quickstart", { headers: { "cf-connecting-ip": "198.51.100.7" } });
  const sent = calls[0].request;
  assert.equal(new URL(sent.url).host, "filetrace.mintlify.site");
  assert.equal(sent.headers.get("x-forwarded-host"), "filetrace.eorlov.org");
  assert.equal(sent.headers.get("x-forwarded-proto"), "https");
  assert.equal(sent.headers.get("x-forwarded-for"), "198.51.100.7");
  assert.equal(calls[0].init.redirect, "manual");
});

test("a redirect to Mintlify's host points at the public host", async () => {
  mintlify((request) => {
    const to = new URL(request.url).pathname === "/old" ? "https://filetrace.mintlify.site/new?a=1"
                                                         : "https://example.org/elsewhere";
    return new Response(null, { status: 301, headers: { location: to } });
  });
  let { response } = await call("/old");
  assert.equal(response.status, 301);
  assert.equal(response.headers.get("location"), "https://filetrace.eorlov.org/new?a=1");
  ({ response } = await call("/away"));
  assert.equal(response.headers.get("location"), "https://example.org/elsewhere");
});

test("lists of pages name the public host, HTML is left as it is", async () => {
  const bodies = {
    "/sitemap.xml": ["text/xml", "<loc>https://filetrace.mintlify.app/cli/files</loc>"],
    "/robots.txt": ["text/plain", "Sitemap: https://filetrace.mintlify.app/sitemap.xml"],
    "/llms.txt": ["text/plain; charset=utf-8", "- [x](https://filetrace.mintlify.site/x.md)"],
    "/quickstart": ["text/html", "<a href=\"https://filetrace.mintlify.app/\">"],
  };
  mintlify((request) => {
    const [type, text] = bodies[new URL(request.url).pathname];
    return new Response(text, { headers: { "content-type": type, "content-length": String(text.length), etag: '"m"' } });
  });
  const expected = {
    "/sitemap.xml": "<loc>https://filetrace.eorlov.org/cli/files</loc>",
    "/robots.txt": "Sitemap: https://filetrace.eorlov.org/sitemap.xml",
    "/llms.txt": "- [x](https://filetrace.eorlov.org/x.md)",
    "/quickstart": bodies["/quickstart"][1],
  };
  for (const [path, text] of Object.entries(expected)) {
    const { response } = await call(path);
    assert.equal(await response.text(), text, path);
    if (path !== "/quickstart") {
      assert.equal(response.headers.get("content-length"), null, path);
      assert.equal(response.headers.get("etag"), null, path);
    }
  }
});
