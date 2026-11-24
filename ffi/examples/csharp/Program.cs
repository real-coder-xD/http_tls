// Language: C# (.NET 8+) | File: ffi/examples/csharp/Program.cs | Target: P/Invoke wrapper & live test for http_tls.dll
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

public sealed class HttpTlsNative : IDisposable
{
    private const string LibName = "http_tls";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_version();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_presets();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_create_session(IntPtr configJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_request(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_gather(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_get_cookies(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_set_cookies(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_set_impersonate(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_destroy_session(IntPtr sessionId);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr http_tls_extract(IntPtr requestJson);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void http_tls_free_string(IntPtr ptr);

    private readonly string _sessionId;
    private bool _disposed;

    public HttpTlsNative(object? config = null)
    {
        var res = CallJson(http_tls_create_session, config ?? new { impersonate = "chrome_149" });
        if (res["ok"]?.GetValue<bool>() != true)
            throw new InvalidOperationException($"create_session failed: {res["error"]}");
        _sessionId = res["session_id"]!.GetValue<string>();
    }

    public static JsonNode Version() => Consume(http_tls_version());
    public static JsonNode Presets() => Consume(http_tls_presets());

    public JsonNode Request(Dictionary<string, object?> req)
    {
        var payload = new Dictionary<string, object?>(req) { ["session_id"] = _sessionId };
        return CallJson(http_tls_request, payload);
    }

    public JsonNode Gather(object[] requests, int concurrency = 50) =>
        CallJson(http_tls_gather, new { session_id = _sessionId, concurrency, requests });

    public JsonNode GetCookies(string? url = null) =>
        CallJson(http_tls_get_cookies, url is null
            ? new { session_id = _sessionId }
            : (object)new { session_id = _sessionId, url });

    public JsonNode SetCookies(object cookies, string? url = null, bool clear = false) =>
        CallJson(http_tls_set_cookies, new { session_id = _sessionId, url, clear, cookies });

    public JsonNode SetImpersonate(string preset) =>
        CallJson(http_tls_set_impersonate, new { session_id = _sessionId, impersonate = preset });

    public static JsonNode Extract(object query) => CallJson(http_tls_extract, query);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        using var sidPtr = Utf8Ptr.From(_sessionId);
        Consume(http_tls_destroy_session(sidPtr.Ptr));
    }

    private static JsonNode CallJson(Func<IntPtr, IntPtr> fn, object payload)
    {
        var json = JsonSerializer.Serialize(payload);
        using var utf8 = Utf8Ptr.From(json);
        return Consume(fn(utf8.Ptr));
    }

    private static JsonNode Consume(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            throw new InvalidOperationException("http_tls returned NULL");
        try
        {
            var str = Marshal.PtrToStringUTF8(ptr) ?? "{}";
            return JsonNode.Parse(str)!;
        }
        finally
        {
            http_tls_free_string(ptr);
        }
    }

    private readonly struct Utf8Ptr : IDisposable
    {
        public IntPtr Ptr { get; }
        private Utf8Ptr(IntPtr ptr) => Ptr = ptr;

        public static Utf8Ptr From(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var mem = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, mem, bytes.Length);
            Marshal.WriteByte(mem, bytes.Length, 0);
            return new Utf8Ptr(mem);
        }

        public void Dispose()
        {
            if (Ptr != IntPtr.Zero) Marshal.FreeHGlobal(Ptr);
        }
    }
}

class Program
{
    static int Main()
    {
        var ver = HttpTlsNative.Version();
        Console.WriteLine($"[C#] http_tls v{ver["version"]} | presets={ver["presets_count"]}");

        using var client = new HttpTlsNative(new
        {
            impersonate = "chrome_149",
            http3 = true,
            ech = true,
            doh = true,
            timeout = 20.0
        });

        var resp = client.Request(new Dictionary<string, object?>
        {
            ["method"] = "GET",
            ["url"] = "https://cloudflare-ech.com/cdn-cgi/trace"
        });

        if (resp["ok"]?.GetValue<bool>() != true)
        {
            Console.Error.WriteLine($"Request failed: {resp}");
            return 1;
        }

        var body = resp["body"]!.GetValue<string>();
        var sni = HttpTlsNative.Extract(new { content = body, left = "sni=", right = "\n", first = true });
        var kex = HttpTlsNative.Extract(new { content = body, left = "kex=", right = "\n", first = true });
        Console.WriteLine($"[C#] {resp["http_version"]} {resp["status_code"]} | ech_accepted={resp["ech_accepted"]} | sni={sni["result"]} | kex={kex["result"]}");

        var extracted = HttpTlsNative.Extract(new
        {
            html = "<div><h1>Hello C#</h1><span class='price'>$19.99</span></div>",
            css = "h1::text, .price::text"
        });
        Console.WriteLine($"[C#] Rust CSS3 extract => {extracted["result"]}");
        return 0;
    }
}
