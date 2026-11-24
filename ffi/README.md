# `http_tls` Standalone C-ABI Shared Library (`ffi/`)

Builds a standalone native shared library (`http_tls.dll` / `libhttp_tls.so` / `libhttp_tls.dylib`) with **zero Python runtime dependency** (`pyo3` is completely excluded at compile time).

## Build

```bash
# From repo root:
cargo build --release --manifest-path ffi/Cargo.toml --target-dir target
```

Output:
- **Windows:** `target/release/http_tls.dll` + `target/release/http_tls.dll.lib`
- **Linux:** `target/release/libhttp_tls.so`
- **macOS:** `target/release/libhttp_tls.dylib`
- **C/C++ Header:** `include/http_tls.h`

## Run Examples

- **Go (Windows, zero-CGO):**
  ```powershell
  $env:HTTP_TLS_DLL = "..\..\target\release\http_tls.dll"
  cd ffi\examples\go && go run .
  ```
- **C# (.NET 8+):**
  ```powershell
  Copy-Item target\release\http_tls.dll ffi\examples\csharp\
  cd ffi\examples\csharp && dotnet run -c Release
  ```
- **Node.js (`koffi`):**
  ```bash
  cd ffi/examples/nodejs && npm install
  HTTP_TLS_LIB=../../../target/release/http_tls.dll node example.mjs
  ```

## Full Documentation

See [`docs/c-abi.md`](../docs/c-abi.md) for all 19 exported functions, JSON request/response schemas, streaming, full-duplex WebSockets, Rust extraction, error codes, and PHP / C / C++ snippets.
