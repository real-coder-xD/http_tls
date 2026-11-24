// Language: Go 1.21+ | File: ffi/examples/go/main.go | Target: Zero-CGO Windows DLL caller for http_tls.dll
//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type HttpTls struct {
	dll            *syscall.LazyDLL
	fnVersion      *syscall.LazyProc
	fnCreateSess   *syscall.LazyProc
	fnRequest      *syscall.LazyProc
	fnExtract      *syscall.LazyProc
	fnDestroySess  *syscall.LazyProc
	fnFreeString   *syscall.LazyProc
}

func OpenHttpTls(dllPath string) *HttpTls {
	dll := syscall.NewLazyDLL(dllPath)
	return &HttpTls{
		dll:           dll,
		fnVersion:     dll.NewProc("http_tls_version"),
		fnCreateSess:  dll.NewProc("http_tls_create_session"),
		fnRequest:     dll.NewProc("http_tls_request"),
		fnExtract:     dll.NewProc("http_tls_extract"),
		fnDestroySess: dll.NewProc("http_tls_destroy_session"),
		fnFreeString:  dll.NewProc("http_tls_free_string"),
	}
}

func (h *HttpTls) consume(ptr uintptr) (map[string]any, error) {
	if ptr == 0 {
		return nil, fmt.Errorf("http_tls returned NULL")
	}
	defer h.fnFreeString.Call(ptr)
	// Walk NUL-terminated UTF-8 C string returned by Rust.
	var length int
	for *(*byte)(unsafe.Pointer(ptr + uintptr(length))) != 0 {
		length++
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *HttpTls) callJSON(proc *syscall.LazyProc, payload any) (map[string]any, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	buf := append(b, 0)
	ptr, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])))
	return h.consume(ptr)
}

func main() {
	dllPath := os.Getenv("HTTP_TLS_DLL")
	if dllPath == "" {
		dllPath = "http_tls.dll"
	}
	lib := OpenHttpTls(dllPath)

	vptr, _, _ := lib.fnVersion.Call()
	ver, err := lib.consume(vptr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[Go] http_tls v%v | presets=%v\n", ver["version"], ver["presets_count"])

	sess, err := lib.callJSON(lib.fnCreateSess, map[string]any{
		"impersonate": "chrome_149",
		"http3":       true,
		"ech":         true,
		"doh":         true,
		"timeout":     20.0,
	})
	if err != nil || sess["ok"] != true {
		panic(fmt.Sprintf("create_session failed: %v %v", sess, err))
	}
	sid := sess["session_id"].(string)
	defer func() {
		buf := append([]byte(sid), 0)
		p, _, _ := lib.fnDestroySess.Call(uintptr(unsafe.Pointer(&buf[0])))
		_, _ = lib.consume(p)
	}()

	resp, err := lib.callJSON(lib.fnRequest, map[string]any{
		"session_id": sid,
		"method":     "GET",
		"url":        "https://cloudflare-ech.com/cdn-cgi/trace",
	})
	if err != nil || resp["ok"] != true {
		panic(fmt.Sprintf("request failed: %v %v", resp, err))
	}
	body := resp["body"].(string)
	sni, _ := lib.callJSON(lib.fnExtract, map[string]any{
		"content": body,
		"left":    "sni=",
		"right":   "\n",
		"first":   true,
	})
	fmt.Printf("[Go] %v %v | ech_accepted=%v | sni=%v\n",
		resp["http_version"], resp["status_code"], resp["ech_accepted"], sni["result"])
}
