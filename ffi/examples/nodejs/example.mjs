// Language: Node.js (ESM) | File: ffi/examples/nodejs/example.mjs | Target: Cross-platform FFI caller via koffi
import koffi from "koffi";
import path from "node:path";

const defaultLib =
  process.platform === "win32"
    ? "http_tls.dll"
    : process.platform === "darwin"
      ? "libhttp_tls.dylib"
      : "libhttp_tls.so";

const libPath = process.env.HTTP_TLS_LIB || path.resolve(defaultLib);
const lib = koffi.load(libPath);

const fnVersion = lib.func("void* http_tls_version()");
const fnCreateSession = lib.func("void* http_tls_create_session(const char*)");
const fnRequest = lib.func("void* http_tls_request(const char*)");
const fnExtract = lib.func("void* http_tls_extract(const char*)");
const fnDestroySession = lib.func("void* http_tls_destroy_session(const char*)");
const fnFreeString = lib.func("void http_tls_free_string(void*)");

function consume(ptr) {
  if (!ptr) throw new Error("http_tls returned NULL");
  try {
    return JSON.parse(koffi.decode(ptr, "char", -1));
  } finally {
    fnFreeString(ptr);
  }
}

const ver = consume(fnVersion());
console.log(`[Node] http_tls v${ver.version} | presets=${ver.presets_count}`);

const { session_id } = consume(
  fnCreateSession(
    JSON.stringify({
      impersonate: "chrome_149",
      http3: true,
      ech: true,
      doh: true,
      timeout: 20,
    }),
  ),
);

try {
  const resp = consume(
    fnRequest(
      JSON.stringify({
        session_id,
        method: "GET",
        url: "https://cloudflare-ech.com/cdn-cgi/trace",
      }),
    ),
  );
  if (!resp.ok) throw new Error(resp.error);

  const sni = consume(
    fnExtract(JSON.stringify({ content: resp.body, left: "sni=", right: "\n", first: true })),
  );
  console.log(
    `[Node] ${resp.http_version} ${resp.status_code} | ech_accepted=${resp.ech_accepted} | sni=${sni.result}`,
  );
} finally {
  consume(fnDestroySession(session_id));
}
