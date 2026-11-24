// Language: Rust 2021 | File: ffi/src/lib.rs | Target: Standalone C-ABI Shared Library (http_tls.dll / libhttp_tls.so / libhttp_tls.dylib)
//! Zero-Python-dependency C-ABI exports. Every `#[no_mangle] pub unsafe extern "C"` symbol lives
//! directly in this cdylib crate so linkers (MSVC, lld, GNU ld, ld64) export every symbol cleanly.

use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn http_tls_version() -> *mut c_char {
    http_tls_core::ffi::capi_version()
}

#[no_mangle]
pub extern "C" fn http_tls_presets() -> *mut c_char {
    http_tls_core::ffi::capi_presets()
}

/// # Safety
/// `config_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_create_session(config_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_create_session(config_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_request(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_request(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_gather(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_gather(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_get_cookies(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_get_cookies(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_set_cookies(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_set_cookies(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_set_impersonate(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_set_impersonate(request_json)
}

/// # Safety
/// `session_id` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_destroy_session(session_id: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_destroy_session(session_id)
}

#[no_mangle]
pub extern "C" fn http_tls_destroy_all_sessions() -> *mut c_char {
    http_tls_core::ffi::capi_destroy_all_sessions()
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_stream_open(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_stream_open(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string (raw stream_id or JSON).
#[no_mangle]
pub unsafe extern "C" fn http_tls_stream_read(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_stream_read(request_json)
}

/// # Safety
/// `stream_id` must be NULL or a valid NUL-terminated UTF-8 C string (raw stream_id or JSON).
#[no_mangle]
pub unsafe extern "C" fn http_tls_stream_close(stream_id: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_stream_close(stream_id)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_ws_connect(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_ws_connect(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_ws_send(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_ws_send(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string (raw ws_id or JSON).
#[no_mangle]
pub unsafe extern "C" fn http_tls_ws_recv(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_ws_recv(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string (raw ws_id or JSON).
#[no_mangle]
pub unsafe extern "C" fn http_tls_ws_close(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_ws_close(request_json)
}

/// # Safety
/// `request_json` must be NULL or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn http_tls_extract(request_json: *const c_char) -> *mut c_char {
    http_tls_core::ffi::capi_extract(request_json)
}

/// # Safety
/// `ptr` must be NULL or a pointer previously returned by an `http_tls_*` function and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn http_tls_free_string(ptr: *mut c_char) {
    http_tls_core::ffi::capi_free_string(ptr)
}
