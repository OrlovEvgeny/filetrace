// Serves https://filetrace.eorlov.org: the download site from the R2 bucket
// bound as SITE, and every other path from the documentation on Mintlify.

const DOCS_HOST = "filetrace.mintlify.site";

const DOWNLOADS = /^\/(?:(?:install\.sh|gpg\.key)$|(?:apt|rpm|apk|dist|channels|versions)\/)/;

// Files this site hosts itself, from the R2 bucket: an AI usage policy, the
// security contact and the credits. They are not pages on the docs site, so
// there is nothing to fall back to.
const OWN = new Set(["/ai.txt", "/security.txt", "/.well-known/security.txt", "/humans.txt"]);

// Files the docs site generates for crawlers and language models: robots.txt,
// sitemap.xml, llms.txt and llms-full.txt. A copy is kept in R2 and served from
// the domain, and refreshed through the docs proxy when it has gone stale.
const MIRROR = new Set(["/robots.txt", "/sitemap.xml", "/llms.txt", "/llms-full.txt"]);
const MIRROR_MAX_AGE_MS = 6 * 60 * 60 * 1000;

// Mintlify names its own hosts in the files that list the pages: sitemap.xml,
// robots.txt, llms.txt and the Markdown copies of the pages.
const MINTLIFY_ORIGINS = /https:\/\/filetrace\.mintlify\.(?:app|site)/g;
const TEXT_TYPES = /^(?:text\/(?:plain|markdown|xml)|application\/xml)\b/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (DOWNLOADS.test(url.pathname) || OWN.has(url.pathname)) {
      return download(request, env.SITE, url.pathname);
    }
    if (MIRROR.has(url.pathname)) {
      return mirror(request, env, ctx, url);
    }
    return docs(request, url);
  },
};

// Serves one of the generated discovery files, preferring the R2 copy. A copy
// older than MIRROR_MAX_AGE_MS is refreshed from the docs site in the
// background, so the file stays current without a request ever waiting on R2.
async function mirror(request, env, ctx, url) {
  const bucket = env.SITE;
  const key = url.pathname.slice(1);

  if (request.method === "GET" || request.method === "HEAD") {
    try {
      const object =
        request.method === "HEAD" ? await bucket.head(key) : await bucket.get(key);
      if (object && Date.now() - object.uploaded.getTime() < MIRROR_MAX_AGE_MS) {
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        headers.set("last-modified", object.uploaded.toUTCString());
        headers.set("cache-control", "public, max-age=300");
        headers.set("accept-ranges", "bytes");
        if (request.method === "HEAD") {
          headers.set("content-length", String(object.size));
          return new Response(null, { headers });
        }
        return new Response(object.body, { headers });
      }
    } catch {
      // A missing or unreadable copy just falls through to the docs site.
    }
  }

  const response = await docs(request, url);
  const type = response.headers.get("content-type") ?? "";
  if (request.method === "GET" && response.status === 200 && TEXT_TYPES.test(type)) {
    const body = response.clone().arrayBuffer();
    ctx.waitUntil(
      body.then((bytes) => bucket.put(key, bytes, { httpMetadata: { contentType: type } })),
    );
  }
  return response;
}

async function download(request, bucket, pathname) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed\n", { status: 405, headers: { allow: "GET, HEAD" } });
  }
  let key;
  try {
    key = decodeURIComponent(pathname.slice(1));
  } catch {
    return new Response("Bad request\n", { status: 400 });
  }

  let object;
  try {
    object =
      request.method === "HEAD"
        ? await bucket.head(key)
        : await bucket.get(key, { range: request.headers, onlyIf: request.headers });
  } catch (error) {
    // R2 rejects a Range header it cannot satisfy instead of returning the object.
    if (request.headers.has("range")) {
      return new Response("Range not satisfiable\n", { status: 416 });
    }
    throw error;
  }
  if (object === null) {
    return new Response("Not found\n", { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("last-modified", object.uploaded.toUTCString());
  headers.set("accept-ranges", "bytes");

  if (request.method === "HEAD") {
    headers.set("content-length", String(object.size));
    return new Response(null, { headers });
  }
  // get() returns an object whose body is undefined when a precondition of onlyIf fails.
  if (object.body === undefined) {
    const notModified = request.headers.has("if-none-match") || request.headers.has("if-modified-since");
    return new Response(null, { status: notModified ? 304 : 412, headers });
  }
  if (request.headers.has("range") && object.range) {
    const { offset, length } = resolveRange(object.range, object.size);
    headers.set("content-range", `bytes ${offset}-${offset + length - 1}/${object.size}`);
    return new Response(object.body, { status: 206, headers });
  }
  return new Response(object.body, { headers });
}

function resolveRange(range, size) {
  if ("suffix" in range) {
    const length = Math.min(range.suffix, size);
    return { offset: size - length, length };
  }
  const offset = range.offset ?? 0;
  return { offset, length: range.length ?? size - offset };
}

async function docs(request, url) {
  const publicHost = url.host;
  const target = new URL(url);
  target.protocol = "https:";
  target.host = DOCS_HOST;

  const proxied = new Request(target, request);
  const client = request.headers.get("cf-connecting-ip");
  proxied.headers.set("origin", DOCS_HOST);
  proxied.headers.set("x-forwarded-host", publicHost);
  proxied.headers.set("x-forwarded-proto", "https");
  if (client) {
    proxied.headers.set("x-forwarded-for", client);
    proxied.headers.set("x-real-ip", client);
  }

  const response = await fetch(proxied, { redirect: "manual" });
  const location = response.headers.get("location");
  if (!location) {
    if (request.method === "GET" && TEXT_TYPES.test(response.headers.get("content-type") ?? "")) {
      return withPublicOrigin(response, `https://${publicHost}`);
    }
    return response;
  }
  const next = new URL(location, target);
  if (next.host !== DOCS_HOST) {
    return response;
  }
  next.protocol = "https:";
  next.host = publicHost;
  const rewritten = new Response(response.body, response);
  rewritten.headers.set("location", next.toString());
  return rewritten;
}

async function withPublicOrigin(response, origin) {
  const text = await response.text();
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("etag");
  return new Response(text.replace(MINTLIFY_ORIGINS, origin), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
