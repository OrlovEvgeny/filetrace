// Serves https://filetrace.eorlov.org: the download site from the R2 bucket
// bound as SITE, and every other path from the documentation on Mintlify.

const DOCS_HOST = "filetrace.mintlify.site";

const DOWNLOADS = /^\/(?:(?:install\.sh|gpg\.key)$|(?:apt|rpm|apk|dist|channels|versions)\/)/;

// Mintlify names its own hosts in the files that list the pages: sitemap.xml,
// robots.txt, llms.txt and the Markdown copies of the pages.
const MINTLIFY_ORIGINS = /https:\/\/filetrace\.mintlify\.(?:app|site)/g;
const TEXT_TYPES = /^(?:text\/(?:plain|markdown|xml)|application\/xml)\b/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (DOWNLOADS.test(url.pathname)) {
      return download(request, env.SITE, url.pathname);
    }
    return docs(request, url);
  },
};

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
  // get() returns no body when a precondition of onlyIf fails.
  if (!("body" in object)) {
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
