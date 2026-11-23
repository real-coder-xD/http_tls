// Language: Rust 2021 | File: src/quic_boring.rs | Target: BoringSSL (btls-sys) QUIC TLS 1.3 & RFC 9001 Crypto Provider for quinn
//! Native BoringSSL QUIC cryptographic provider for `quinn` (`quinn_proto::crypto::{ClientConfig, Session}`).
//!
//! Drives the QUIC TLS 1.3 handshake directly through the embedded BoringSSL (`btls-sys`) via
//! `SSL_set_quic_method`, producing authentic Chromium QUIC Initial `ClientHello` frames
//! (GREASE, extension permutation, Post-Quantum `X25519MLKEM768`, ECH GREASE, ALPS `h3`,
//! and RFC 8879 Brotli certificate compression) and RFC 9001 packet/header protection
//! using BoringSSL's own `EVP_AEAD_CTX`, `HKDF`, `AES_encrypt`, and `CRYPTO_chacha_20`.

use btls_sys as ffi;
use bytes::BytesMut;
use quinn_proto::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::{self, NonNull};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

// RFC 9001 Section 5.2 Initial Salt (QUIC v1) & Retry Integrity Key/Nonce (QUIC v1)
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const CERT_COMP_BROTLI: u16 = 2;
const CERT_COMP_ZLIB: u16 = 1;
const CERT_COMP_ZSTD: u16 = 3;

static KEYLOG_LOCK: Mutex<()> = Mutex::new(());

fn ex_data_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
    })
}

fn keylog_ex_data_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None)
    })
}

fn level_index(level: ffi::ssl_encryption_level_t) -> usize {
    match level {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => 0,
        ffi::ssl_encryption_level_t::ssl_encryption_early_data => 1,
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => 2,
        ffi::ssl_encryption_level_t::ssl_encryption_application => 3,
        _ => 0,
    }
}

/// BoringSSL HMAC-SHA256 key for `quinn::EndpointConfig::new(...)` stateless reset tokens.
pub struct BoringHmacKey([u8; 32]);

impl BoringHmacKey {
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        unsafe {
            ffi::RAND_bytes(key.as_mut_ptr(), key.len());
        }
        Self(key)
    }
}

impl crypto::HmacKey for BoringHmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut out = [0u8; 32];
        let mut out_len: c_uint = 0;
        unsafe {
            ffi::HMAC(
                ffi::EVP_sha256(),
                self.0.as_ptr() as *const c_void,
                self.0.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            );
        }
        let n = signature_out.len().min(32);
        signature_out[..n].copy_from_slice(&out[..n]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != 32 {
            return Err(CryptoError);
        }
        let mut expected = [0u8; 32];
        self.sign(data, &mut expected);
        let eq = unsafe {
            ffi::CRYPTO_memcmp(
                expected.as_ptr() as *const c_void,
                signature.as_ptr() as *const c_void,
                32,
            )
        };
        if eq == 0 {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

fn last_boring_error() -> String {
    unsafe {
        let code = ffi::ERR_get_error();
        if code == 0 {
            return "BoringSSL handshake error".to_string();
        }
        let mut buf = [0u8; 256];
        ffi::ERR_error_string_n(code, buf.as_mut_ptr() as *mut c_char, buf.len());
        CStr::from_ptr(buf.as_ptr() as *const c_char)
            .to_string_lossy()
            .into_owned()
    }
}

// ---------------------------------------------------------------------------
// RFC 8879 Certificate Decompression Callbacks (Brotli, Zlib, Zstd)
// ---------------------------------------------------------------------------
unsafe extern "C" fn cert_decompress_brotli(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> c_int {
    if in_ptr.is_null() || out.is_null() || uncompressed_len > 1024 * 1024 {
        return 0;
    }
    let input = std::slice::from_raw_parts(in_ptr, in_len);
    let mut dec = brotli::Decompressor::new(input, 4096);
    let mut decoded = Vec::with_capacity(uncompressed_len);
    if dec.read_to_end(&mut decoded).is_err() || decoded.len() != uncompressed_len {
        return 0;
    }
    let buf = ffi::CRYPTO_BUFFER_new(decoded.as_ptr(), decoded.len(), ptr::null_mut());
    if buf.is_null() {
        return 0;
    }
    *out = buf;
    1
}

unsafe extern "C" fn cert_decompress_zlib(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> c_int {
    if in_ptr.is_null() || out.is_null() || uncompressed_len > 1024 * 1024 {
        return 0;
    }
    let input = std::slice::from_raw_parts(in_ptr, in_len);
    let mut dec = flate2::read::ZlibDecoder::new(input);
    let mut decoded = Vec::with_capacity(uncompressed_len);
    if dec.read_to_end(&mut decoded).is_err() || decoded.len() != uncompressed_len {
        return 0;
    }
    let buf = ffi::CRYPTO_BUFFER_new(decoded.as_ptr(), decoded.len(), ptr::null_mut());
    if buf.is_null() {
        return 0;
    }
    *out = buf;
    1
}

unsafe extern "C" fn cert_decompress_zstd(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_ptr: *const u8,
    in_len: usize,
) -> c_int {
    if in_ptr.is_null() || out.is_null() || uncompressed_len > 1024 * 1024 {
        return 0;
    }
    let input = std::slice::from_raw_parts(in_ptr, in_len);
    let decoded = match zstd::stream::decode_all(input) {
        Ok(d) if d.len() == uncompressed_len => d,
        _ => return 0,
    };
    let buf = ffi::CRYPTO_BUFFER_new(decoded.as_ptr(), decoded.len(), ptr::null_mut());
    if buf.is_null() {
        return 0;
    }
    *out = buf;
    1
}

unsafe extern "C" fn keylog_cb(ssl: *const ffi::SSL, line: *const c_char) {
    if ssl.is_null() || line.is_null() {
        return;
    }
    let ctx = ffi::SSL_get_SSL_CTX(ssl);
    if ctx.is_null() {
        return;
    }
    let path_ptr = ffi::SSL_CTX_get_ex_data(ctx, keylog_ex_data_idx()) as *const c_char;
    let target_path = if !path_ptr.is_null() {
        CStr::from_ptr(path_ptr).to_string_lossy().into_owned()
    } else if let Ok(p) = std::env::var("SSLKEYLOGFILE") {
        if p.trim().is_empty() {
            return;
        }
        p
    } else {
        return;
    };
    let line_str = CStr::from_ptr(line).to_string_lossy();
    let _guard = KEYLOG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if let Ok(mut fh) = OpenOptions::new().create(true).append(true).open(&target_path) {
        let _ = writeln!(fh, "{line_str}");
    }
}

// ---------------------------------------------------------------------------
// RFC 9001 HKDF-Expand-Label, PacketKey (EVP_AEAD_CTX), HeaderKey (AES/ChaCha20)
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq)]
enum QuicCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl QuicCipher {
    fn from_cipher_id(id: u16) -> Option<Self> {
        match id {
            TLS13_AES_128_GCM_SHA256 => Some(Self::Aes128Gcm),
            TLS13_AES_256_GCM_SHA384 => Some(Self::Aes256Gcm),
            TLS13_CHACHA20_POLY1305_SHA256 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 48,
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    unsafe fn md(self) -> *const ffi::EVP_MD {
        match self {
            Self::Aes256Gcm => ffi::EVP_sha384(),
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => ffi::EVP_sha256(),
        }
    }

    unsafe fn aead(self) -> *const ffi::EVP_AEAD {
        match self {
            Self::Aes128Gcm => ffi::EVP_aead_aes_128_gcm(),
            Self::Aes256Gcm => ffi::EVP_aead_aes_256_gcm(),
            Self::ChaCha20Poly1305 => ffi::EVP_aead_chacha20_poly1305(),
        }
    }
}

fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut out_len: usize = 0;
    unsafe {
        ffi::HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            ffi::EVP_sha256(),
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
        );
    }
    out
}

fn hkdf_expand_label(cipher: QuicCipher, secret: &[u8], label: &[u8], out: &mut [u8]) {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context
    unsafe {
        ffi::HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            cipher.md(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        );
    }
}

struct BoringPacketKey {
    ctx: Box<ffi::EVP_AEAD_CTX>,
    iv: [u8; 12],
    cipher: QuicCipher,
}

// SAFETY: BoringSSL `EVP_AEAD_CTX` is documented immutable and safe for concurrent seal/open calls.
unsafe impl Send for BoringPacketKey {}
unsafe impl Sync for BoringPacketKey {}

impl Drop for BoringPacketKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_AEAD_CTX_cleanup(&mut *self.ctx);
        }
    }
}

impl BoringPacketKey {
    fn from_secret(cipher: QuicCipher, secret: &[u8]) -> Self {
        let mut key = vec![0u8; cipher.key_len()];
        let mut iv = [0u8; 12];
        hkdf_expand_label(cipher, secret, b"quic key", &mut key);
        hkdf_expand_label(cipher, secret, b"quic iv", &mut iv);

        let mut ctx: Box<ffi::EVP_AEAD_CTX> = Box::new(unsafe { std::mem::zeroed() });
        unsafe {
            ffi::EVP_AEAD_CTX_init(
                &mut *ctx,
                cipher.aead(),
                key.as_ptr(),
                key.len(),
                16,
                ptr::null_mut(),
            );
        }
        Self { ctx, iv, cipher }
    }

    fn make_nonce(&self, packet: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let pn = packet.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= pn[i];
        }
        nonce
    }
}

impl PacketKey for BoringPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce = self.make_nonce(packet);
        let (header, payload_and_tag) = buf.split_at_mut(header_len);
        let payload_len = payload_and_tag.len() - 16;
        let (payload, tag) = payload_and_tag.split_at_mut(payload_len);
        let mut tag_len: usize = 0;
        unsafe {
            let ok = ffi::EVP_AEAD_CTX_seal_scatter(
                &*self.ctx,
                payload.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut tag_len,
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.as_ptr(),
                payload.len(),
                ptr::null(),
                0,
                header.as_ptr(),
                header.len(),
            );
            debug_assert_eq!(ok, 1);
            debug_assert_eq!(tag_len, 16);
        }
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        if payload.len() < 16 {
            return Err(CryptoError);
        }
        let nonce = self.make_nonce(packet);
        let mut out_len: usize = 0;
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_open(
                &*self.ctx,
                payload.as_mut_ptr(),
                &mut out_len,
                payload.len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.as_ptr(),
                payload.len(),
                header.as_ptr(),
                header.len(),
            )
        };
        if ok != 1 {
            return Err(CryptoError);
        }
        payload.truncate(out_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        match self.cipher {
            QuicCipher::Aes128Gcm | QuicCipher::Aes256Gcm => 1 << 23,
            QuicCipher::ChaCha20Poly1305 => u64::MAX,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.cipher {
            QuicCipher::Aes128Gcm | QuicCipher::Aes256Gcm => 1 << 52,
            QuicCipher::ChaCha20Poly1305 => 1 << 36,
        }
    }
}

enum BoringHeaderKey {
    Aes(Box<ffi::AES_KEY>),
    ChaCha20([u8; 32]),
}

// SAFETY: `AES_KEY` and `[u8; 32]` are immutable read-only key schedules after construction.
unsafe impl Send for BoringHeaderKey {}
unsafe impl Sync for BoringHeaderKey {}

impl BoringHeaderKey {
    fn from_secret(cipher: QuicCipher, secret: &[u8]) -> Self {
        match cipher {
            QuicCipher::Aes128Gcm => {
                let mut hp = [0u8; 16];
                hkdf_expand_label(cipher, secret, b"quic hp", &mut hp);
                let mut aes_key: Box<ffi::AES_KEY> = Box::new(unsafe { std::mem::zeroed() });
                unsafe {
                    ffi::AES_set_encrypt_key(hp.as_ptr(), 128, &mut *aes_key);
                }
                Self::Aes(aes_key)
            }
            QuicCipher::Aes256Gcm => {
                let mut hp = [0u8; 32];
                hkdf_expand_label(cipher, secret, b"quic hp", &mut hp);
                let mut aes_key: Box<ffi::AES_KEY> = Box::new(unsafe { std::mem::zeroed() });
                unsafe {
                    ffi::AES_set_encrypt_key(hp.as_ptr(), 256, &mut *aes_key);
                }
                Self::Aes(aes_key)
            }
            QuicCipher::ChaCha20Poly1305 => {
                let mut hp = [0u8; 32];
                hkdf_expand_label(cipher, secret, b"quic hp", &mut hp);
                Self::ChaCha20(hp)
            }
        }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        match self {
            Self::Aes(aes_key) => {
                let mut block = [0u8; 16];
                unsafe {
                    ffi::AES_encrypt(sample.as_ptr(), block.as_mut_ptr(), &**aes_key);
                }
                [block[0], block[1], block[2], block[3], block[4]]
            }
            Self::ChaCha20(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce = &sample[4..16];
                let zeros = [0u8; 5];
                let mut out = [0u8; 5];
                unsafe {
                    ffi::CRYPTO_chacha_20(
                        out.as_mut_ptr(),
                        zeros.as_ptr(),
                        5,
                        key.as_ptr(),
                        nonce.as_ptr(),
                        counter,
                    );
                }
                out
            }
        }
    }
}

impl HeaderKey for BoringHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.mask(&sample[..16]);
        let is_long = (header[0] & 0x80) != 0;
        header[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        let pn_len = ((header[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let mask = self.mask(&sample[..16]);
        let is_long = (header[0] & 0x80) != 0;
        let pn_len = ((header[0] & 0x03) + 1) as usize;
        header[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn sample_size(&self) -> usize {
        16
    }
}

fn derive_keys_pair(cipher: QuicCipher, local_secret: &[u8], remote_secret: &[u8]) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(BoringHeaderKey::from_secret(cipher, local_secret)),
            remote: Box::new(BoringHeaderKey::from_secret(cipher, remote_secret)),
        },
        packet: KeyPair {
            local: Box::new(BoringPacketKey::from_secret(cipher, local_secret)),
            remote: Box::new(BoringPacketKey::from_secret(cipher, remote_secret)),
        },
    }
}

// ---------------------------------------------------------------------------
// BoringSSL SSL_QUIC_METHOD callbacks
// ---------------------------------------------------------------------------
struct BoringQuicState {
    write_bufs: [Vec<u8>; 4],
    read_secrets: [Option<(QuicCipher, Vec<u8>)>; 4],
    write_secrets: [Option<(QuicCipher, Vec<u8>)>; 4],
    alert: Option<u8>,
}

impl BoringQuicState {
    fn new() -> Self {
        Self {
            write_bufs: Default::default(),
            read_secrets: Default::default(),
            write_secrets: Default::default(),
            alert: None,
        }
    }
}

unsafe fn state_from_ssl<'a>(ssl: *mut ffi::SSL) -> Option<&'a mut BoringQuicState> {
    let ptr = ffi::SSL_get_ex_data(ssl, ex_data_idx()) as *mut BoringQuicState;
    ptr.as_mut()
}

unsafe extern "C" fn quic_set_read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let Some(st) = state_from_ssl(ssl) else {
        return 0;
    };
    let cid = (ffi::SSL_CIPHER_get_id(cipher) & 0xffff) as u16;
    let Some(qc) = QuicCipher::from_cipher_id(cid) else {
        return 0;
    };
    let sec = std::slice::from_raw_parts(secret, secret_len).to_vec();
    st.read_secrets[level_index(level)] = Some((qc, sec));
    1
}

unsafe extern "C" fn quic_set_write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let Some(st) = state_from_ssl(ssl) else {
        return 0;
    };
    let cid = (ffi::SSL_CIPHER_get_id(cipher) & 0xffff) as u16;
    let Some(qc) = QuicCipher::from_cipher_id(cid) else {
        return 0;
    };
    let sec = std::slice::from_raw_parts(secret, secret_len).to_vec();
    st.write_secrets[level_index(level)] = Some((qc, sec));
    1
}

unsafe extern "C" fn quic_add_handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(st) = state_from_ssl(ssl) else {
        return 0;
    };
    if !data.is_null() && len > 0 {
        let slice = std::slice::from_raw_parts(data, len);
        st.write_bufs[level_index(level)].extend_from_slice(slice);
    }
    1
}

unsafe extern "C" fn quic_flush_flight(_ssl: *mut ffi::SSL) -> c_int {
    1
}

unsafe extern "C" fn quic_send_alert(
    ssl: *mut ffi::SSL,
    _level: ffi::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    if let Some(st) = state_from_ssl(ssl) {
        st.alert = Some(alert);
    }
    1
}

static BORING_QUIC_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(quic_set_read_secret),
    set_write_secret: Some(quic_set_write_secret),
    add_handshake_data: Some(quic_add_handshake_data),
    flush_flight: Some(quic_flush_flight),
    send_alert: Some(quic_send_alert),
};

/// Handshake metadata exposed via `quinn::Connection::handshake_data()`.
#[derive(Clone, Debug)]
pub struct BoringHandshakeData {
    #[allow(dead_code)]
    pub protocol: Option<Vec<u8>>,
    pub ech_accepted: bool,
}

// ---------------------------------------------------------------------------
// BoringQuicClientConfig (implements quinn_proto::crypto::ClientConfig)
// ---------------------------------------------------------------------------
pub struct BoringQuicClientConfig {
    ctx: NonNull<ffi::SSL_CTX>,
    keylog_path: Option<CString>,
    verify: bool,
    chrome_alps: bool,
    ech_grease: bool,
    ech_config_list: Option<Vec<u8>>,
    ech_retry_out: Arc<Mutex<Option<Vec<u8>>>>,
}

// SAFETY: `SSL_CTX` is read-only after construction and safe for concurrent `SSL_new(ctx)`.
unsafe impl Send for BoringQuicClientConfig {}
unsafe impl Sync for BoringQuicClientConfig {}

impl Drop for BoringQuicClientConfig {
    fn drop(&mut self) {
        unsafe {
            ffi::SSL_CTX_free(self.ctx.as_ptr());
        }
        // `keylog_path` drops after `SSL_CTX_free` so ex_data pointer stays valid until freed.
        let _ = &self.keylog_path;
    }
}

fn load_ca_certs_into_store(store: *mut ffi::X509_STORE, ca_bundle: Option<&[u8]>) {
    unsafe {
        // 1. Load embedded Mozilla WebPKI root certificates (DER)
        for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            let mut ptr = der.as_ref().as_ptr();
            let x509 = ffi::d2i_X509(ptr::null_mut(), &mut ptr, der.as_ref().len() as _);
            if !x509.is_null() {
                ffi::X509_STORE_add_cert(store, x509);
                ffi::X509_free(x509);
            }
        }
        // 2. Load optional user-provided CA bundle (PEM stack or DER)
        if let Some(raw) = ca_bundle {
            let bio = ffi::BIO_new_mem_buf(raw.as_ptr() as *const c_void, raw.len() as isize);
            let mut added_pem = false;
            if !bio.is_null() {
                loop {
                    let x509 = ffi::PEM_read_bio_X509(bio, ptr::null_mut(), None, ptr::null_mut());
                    if x509.is_null() {
                        break;
                    }
                    ffi::X509_STORE_add_cert(store, x509);
                    ffi::X509_free(x509);
                    added_pem = true;
                }
                ffi::BIO_free(bio);
            }
            ffi::ERR_clear_error();
            if !added_pem {
                let mut ptr = raw.as_ptr();
                let x509 = ffi::d2i_X509(ptr::null_mut(), &mut ptr, raw.len() as _);
                if !x509.is_null() {
                    ffi::X509_STORE_add_cert(store, x509);
                    ffi::X509_free(x509);
                }
            }
        }
    }
}

fn load_client_identity(ctx: *mut ffi::SSL_CTX, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
    unsafe {
        let cbio = ffi::BIO_new_mem_buf(cert_pem.as_ptr() as *const c_void, cert_pem.len() as isize);
        if cbio.is_null() {
            return Err("Failed to allocate cert BIO".to_string());
        }
        let leaf = ffi::PEM_read_bio_X509(cbio, ptr::null_mut(), None, ptr::null_mut());
        if leaf.is_null() {
            ffi::BIO_free(cbio);
            return Err(format!("Invalid client certificate PEM: {}", last_boring_error()));
        }
        let ok_cert = ffi::SSL_CTX_use_certificate(ctx, leaf);
        ffi::X509_free(leaf);
        if ok_cert != 1 {
            ffi::BIO_free(cbio);
            return Err(format!("SSL_CTX_use_certificate failed: {}", last_boring_error()));
        }
        // Optional intermediate chain certs
        loop {
            let extra = ffi::PEM_read_bio_X509(cbio, ptr::null_mut(), None, ptr::null_mut());
            if extra.is_null() {
                break;
            }
            ffi::SSL_CTX_add_extra_chain_cert(ctx, extra);
        }
        ffi::BIO_free(cbio);
        ffi::ERR_clear_error();

        let kbio = ffi::BIO_new_mem_buf(key_pem.as_ptr() as *const c_void, key_pem.len() as isize);
        if kbio.is_null() {
            return Err("Failed to allocate key BIO".to_string());
        }
        let pkey = ffi::PEM_read_bio_PrivateKey(kbio, ptr::null_mut(), None, ptr::null_mut());
        ffi::BIO_free(kbio);
        if pkey.is_null() {
            return Err(format!("Invalid client private key PEM: {}", last_boring_error()));
        }
        let ok_key = ffi::SSL_CTX_use_PrivateKey(ctx, pkey);
        ffi::EVP_PKEY_free(pkey);
        if ok_key != 1 {
            return Err(format!("SSL_CTX_use_PrivateKey failed: {}", last_boring_error()));
        }
    }
    Ok(())
}

impl BoringQuicClientConfig {
    pub fn new(
        preset: &str,
        verify: bool,
        ca_bundle: Option<&[u8]>,
        identity_pair: Option<&(Vec<u8>, Vec<u8>)>,
        keylog_file: Option<&str>,
        ech_config_list: Option<Vec<u8>>,
        ech_retry_out: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> Result<Self, String> {
        let lower = preset.trim().to_ascii_lowercase();
        let is_firefox = lower.starts_with("firefox") || lower.starts_with("tor");
        let is_safari = lower.starts_with("safari");

        unsafe {
            let ctx = ffi::SSL_CTX_new(ffi::TLS_client_method());
            let Some(ctx_nn) = NonNull::new(ctx) else {
                return Err("SSL_CTX_new failed".to_string());
            };

            ffi::SSL_CTX_set_min_proto_version(ctx, ffi::TLS1_3_VERSION as u16);
            ffi::SSL_CTX_set_max_proto_version(ctx, ffi::TLS1_3_VERSION as u16);
            ffi::SSL_CTX_set_quic_method(ctx, &BORING_QUIC_METHOD);

            // Authentic browser BoringSSL TLS 1.3 fingerprint settings
            ffi::SSL_CTX_set_grease_enabled(ctx, if is_firefox { 0 } else { 1 });
            ffi::SSL_CTX_set_permute_extensions(ctx, if is_firefox || is_safari { 0 } else { 1 });

            // Curves / KeyShare: Chrome 131+ uses X25519MLKEM768:X25519:P-256:P-384
            let curves = if is_safari {
                "X25519:P-256:P-384:P-521"
            } else if is_firefox {
                "X25519MLKEM768:X25519:P-256:P-384:P-521"
            } else {
                "X25519MLKEM768:X25519:P-256:P-384"
            };
            if let Ok(c_curves) = CString::new(curves) {
                if ffi::SSL_CTX_set1_curves_list(ctx, c_curves.as_ptr()) != 1 {
                    let fallback = CString::new("X25519:P-256:P-384").unwrap();
                    ffi::SSL_CTX_set1_curves_list(ctx, fallback.as_ptr());
                }
            }

            // Signature algorithms matching Chrome / Firefox / Safari
            let sigalgs = if is_safari {
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha384:rsa_pkcs1_sha512"
            } else {
                "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
            };
            if let Ok(c_sig) = CString::new(sigalgs) {
                ffi::SSL_CTX_set1_sigalgs_list(ctx, c_sig.as_ptr());
            }

            // RFC 8879 Certificate Compression (extension 27)
            if is_safari {
                ffi::SSL_CTX_add_cert_compression_alg(ctx, CERT_COMP_ZLIB, None, Some(cert_decompress_zlib));
            } else if is_firefox {
                ffi::SSL_CTX_add_cert_compression_alg(ctx, CERT_COMP_ZLIB, None, Some(cert_decompress_zlib));
                ffi::SSL_CTX_add_cert_compression_alg(ctx, CERT_COMP_BROTLI, None, Some(cert_decompress_brotli));
                ffi::SSL_CTX_add_cert_compression_alg(ctx, CERT_COMP_ZSTD, None, Some(cert_decompress_zstd));
            } else {
                // Chrome uses Brotli cert compression
                ffi::SSL_CTX_add_cert_compression_alg(ctx, CERT_COMP_BROTLI, None, Some(cert_decompress_brotli));
            }

            // ALPN "h3"
            let alpn = b"\x02h3";
            ffi::SSL_CTX_set_alpn_protos(ctx, alpn.as_ptr(), alpn.len());

            // Certificate verification & trust store
            if verify {
                ffi::SSL_CTX_set_verify(ctx, ffi::SSL_VERIFY_PEER, None);
                let store = ffi::SSL_CTX_get_cert_store(ctx);
                if !store.is_null() {
                    load_ca_certs_into_store(store, ca_bundle);
                }
            } else {
                ffi::SSL_CTX_set_verify(ctx, ffi::SSL_VERIFY_NONE, None);
            }

            // Optional mTLS identity
            if let Some((cert_pem, key_pem)) = identity_pair {
                if let Err(e) = load_client_identity(ctx, cert_pem, key_pem) {
                    ffi::SSL_CTX_free(ctx);
                    return Err(e);
                }
            }

            // Optional SSLKEYLOGFILE support
            let mut keylog_cstr: Option<CString> = None;
            let want_env_kl = std::env::var("SSLKEYLOGFILE")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if let Some(kl) = keylog_file {
                if let Ok(c_kl) = CString::new(kl) {
                    ffi::SSL_CTX_set_ex_data(
                        ctx,
                        keylog_ex_data_idx(),
                        c_kl.as_ptr() as *mut c_void,
                    );
                    ffi::SSL_CTX_set_keylog_callback(ctx, Some(keylog_cb));
                    keylog_cstr = Some(c_kl);
                }
            } else if want_env_kl {
                ffi::SSL_CTX_set_keylog_callback(ctx, Some(keylog_cb));
            }

            Ok(Self {
                ctx: ctx_nn,
                keylog_path: keylog_cstr,
                verify,
                chrome_alps: !is_firefox && !is_safari,
                ech_grease: !is_safari,
                ech_config_list,
                ech_retry_out,
            })
        }
    }
}

impl crypto::ClientConfig for BoringQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != 0x0000_0001 {
            return Err(ConnectError::UnsupportedVersion);
        }
        let mut params_bytes = Vec::new();
        params.write(&mut params_bytes);

        let c_sni = CString::new(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.to_string()))?;

        unsafe {
            let ssl = ffi::SSL_new(self.ctx.as_ptr());
            let Some(ssl_nn) = NonNull::new(ssl) else {
                return Err(ConnectError::InvalidServerName(server_name.to_string()));
            };

            let state = Box::new(BoringQuicState::new());
            let state_ptr = &*state as *const BoringQuicState as *mut c_void;
            ffi::SSL_set_ex_data(ssl, ex_data_idx(), state_ptr);

            ffi::SSL_set_connect_state(ssl);
            ffi::SSL_set_tlsext_host_name(ssl, c_sni.as_ptr());

            let mut real_ech_set = false;
            if let Some(ref ech_list) = self.ech_config_list {
                if !ech_list.is_empty()
                    && ffi::SSL_set1_ech_config_list(ssl, ech_list.as_ptr(), ech_list.len()) == 1
                {
                    real_ech_set = true;
                }
            }
            if !real_ech_set && self.ech_grease {
                ffi::SSL_set_enable_ech_grease(ssl, 1);
            }
            if self.chrome_alps {
                ffi::SSL_set_alps_use_new_codepoint(ssl, 1);
                ffi::SSL_add_application_settings(ssl, b"h3".as_ptr(), 2, ptr::null(), 0);
            }

            if self.verify {
                let param = ffi::SSL_get0_param(ssl);
                if !param.is_null() {
                    if IpAddr::from_str(server_name).is_ok() {
                        ffi::X509_VERIFY_PARAM_set1_ip_asc(param, c_sni.as_ptr());
                    } else {
                        ffi::X509_VERIFY_PARAM_set1_host(param, c_sni.as_ptr(), server_name.len());
                    }
                }
            }

            if ffi::SSL_set_quic_transport_params(ssl, params_bytes.as_ptr(), params_bytes.len()) != 1 {
                ffi::SSL_free(ssl);
                return Err(ConnectError::InvalidServerName(server_name.to_string()));
            }

            Ok(Box::new(BoringQuicSession {
                _cfg: self,
                ssl: ssl_nn,
                state,
                handshake_started: false,
                got_handshake_data: false,
                current_level: ffi::ssl_encryption_level_t::ssl_encryption_initial,
                app_secrets: None,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// BoringQuicSession (implements quinn_proto::crypto::Session)
// ---------------------------------------------------------------------------
pub struct BoringQuicSession {
    _cfg: Arc<BoringQuicClientConfig>,
    ssl: NonNull<ffi::SSL>,
    state: Box<BoringQuicState>,
    handshake_started: bool,
    got_handshake_data: bool,
    current_level: ffi::ssl_encryption_level_t,
    app_secrets: Option<(QuicCipher, Vec<u8>, Vec<u8>)>,
}

// SAFETY: `BoringQuicSession` is uniquely owned by a single `quinn_proto::Connection`
// and never shared concurrently across threads.
unsafe impl Send for BoringQuicSession {}
unsafe impl Sync for BoringQuicSession {}

impl Drop for BoringQuicSession {
    fn drop(&mut self) {
        unsafe {
            ffi::SSL_set_ex_data(self.ssl.as_ptr(), ex_data_idx(), ptr::null_mut());
            ffi::SSL_free(self.ssl.as_ptr());
        }
    }
}

impl BoringQuicSession {
    fn capture_ech_retry_configs(&self) {
        unsafe {
            let mut retry_ptr: *const u8 = ptr::null();
            let mut retry_len: usize = 0;
            ffi::SSL_get0_ech_retry_configs(self.ssl.as_ptr(), &mut retry_ptr, &mut retry_len);
            if !retry_ptr.is_null() && retry_len > 0 {
                let slice = std::slice::from_raw_parts(retry_ptr, retry_len).to_vec();
                let mut guard = self._cfg.ech_retry_out.lock().unwrap_or_else(|p| p.into_inner());
                *guard = Some(slice);
            }
        }
    }

    fn drive_handshake(&mut self) -> Result<(), TransportError> {
        unsafe {
            let ret = if ffi::SSL_is_init_finished(self.ssl.as_ptr()) == 1 {
                ffi::SSL_process_quic_post_handshake(self.ssl.as_ptr())
            } else {
                ffi::SSL_do_handshake(self.ssl.as_ptr())
            };
            if let Some(alert) = self.state.alert.take() {
                self.capture_ech_retry_configs();
                return Err(TransportError {
                    code: TransportErrorCode::crypto(alert),
                    frame: None,
                    reason: last_boring_error(),
                });
            }
            if ret <= 0 {
                let err = ffi::SSL_get_error(self.ssl.as_ptr(), ret);
                if err != ffi::SSL_ERROR_WANT_READ && err != ffi::SSL_ERROR_WANT_WRITE {
                    self.capture_ech_retry_configs();
                    return Err(TransportError {
                        code: TransportErrorCode::crypto(0x50), // internal_error / handshake_failure
                        frame: None,
                        reason: last_boring_error(),
                    });
                }
            }
        }
        Ok(())
    }

    fn alpn_protocol(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut ptr: *const u8 = ptr::null();
            let mut len: c_uint = 0;
            ffi::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                None
            } else {
                Some(std::slice::from_raw_parts(ptr, len as usize).to_vec())
            }
        }
    }
}

impl crypto::Session for BoringQuicSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        let initial_secret = hkdf_extract_sha256(&QUIC_V1_INITIAL_SALT, dst_cid);
        let mut client_sec = [0u8; 32];
        let mut server_sec = [0u8; 32];
        hkdf_expand_label(QuicCipher::Aes128Gcm, &initial_secret, b"client in", &mut client_sec);
        hkdf_expand_label(QuicCipher::Aes128Gcm, &initial_secret, b"server in", &mut server_sec);
        match side {
            Side::Client => derive_keys_pair(QuicCipher::Aes128Gcm, &client_sec, &server_sec),
            Side::Server => derive_keys_pair(QuicCipher::Aes128Gcm, &server_sec, &client_sec),
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        let ech_accepted = unsafe { ffi::SSL_ech_accepted(self.ssl.as_ptr()) == 1 };
        Some(Box::new(BoringHandshakeData {
            protocol: self.alpn_protocol(),
            ech_accepted,
        }))
    }

    /// Returns `Vec<Vec<u8>>` containing DER-encoded peer certificates.
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        unsafe {
            let stack = ffi::SSL_get_peer_full_cert_chain(self.ssl.as_ptr());
            if stack.is_null() {
                return None;
            }
            let count = ffi::sk_num(stack as *const ffi::_STACK);
            if count == 0 {
                return None;
            }
            let mut certs = Vec::with_capacity(count);
            for i in 0..count {
                let x509 = ffi::sk_value(stack as *const ffi::_STACK, i) as *const ffi::X509;
                if x509.is_null() {
                    continue;
                }
                let mut der_ptr: *mut u8 = ptr::null_mut();
                let len = ffi::i2d_X509(x509, &mut der_ptr);
                if len > 0 && !der_ptr.is_null() {
                    certs.push(std::slice::from_raw_parts(der_ptr, len as usize).to_vec());
                    ffi::OPENSSL_free(der_ptr as *mut c_void);
                }
            }
            if certs.is_empty() {
                None
            } else {
                Some(Box::new(certs))
            }
        }
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        unsafe { ffi::SSL_is_init_finished(self.ssl.as_ptr()) != 1 }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        unsafe {
            let ok = ffi::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                self.current_level,
                buf.as_ptr(),
                buf.len(),
            );
            if ok != 1 {
                return Err(TransportError {
                    code: TransportErrorCode::PROTOCOL_VIOLATION,
                    frame: None,
                    reason: format!("SSL_provide_quic_data failed: {}", last_boring_error()),
                });
            }
        }
        self.drive_handshake()?;

        if !self.got_handshake_data && (self.alpn_protocol().is_some() || !self.is_handshaking()) {
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        unsafe {
            let mut ptr: *const u8 = ptr::null();
            let mut len: usize = 0;
            ffi::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut ptr, &mut len);
            if ptr.is_null() || len == 0 {
                return Ok(None);
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            match TransportParameters::read(Side::Client, &mut Cursor::new(slice)) {
                Ok(tp) => Ok(Some(tp)),
                Err(e) => Err(e.into()),
            }
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        if !self.handshake_started {
            self.handshake_started = true;
            let _ = self.drive_handshake();
        }

        let cur_idx = level_index(self.current_level);
        if !self.state.write_bufs[cur_idx].is_empty() {
            buf.append(&mut self.state.write_bufs[cur_idx]);
        }

        let next_level = match self.current_level {
            ffi::ssl_encryption_level_t::ssl_encryption_initial => {
                ffi::ssl_encryption_level_t::ssl_encryption_handshake
            }
            ffi::ssl_encryption_level_t::ssl_encryption_handshake => {
                ffi::ssl_encryption_level_t::ssl_encryption_application
            }
            _ => return None,
        };
        let next_idx = level_index(next_level);

        if self.state.read_secrets[next_idx].is_some() && self.state.write_secrets[next_idx].is_some()
        {
            let (rcipher, rsec) = self.state.read_secrets[next_idx].take().unwrap();
            let (wcipher, wsec) = self.state.write_secrets[next_idx].take().unwrap();
            let keys = Keys {
                header: KeyPair {
                    local: Box::new(BoringHeaderKey::from_secret(wcipher, &wsec)),
                    remote: Box::new(BoringHeaderKey::from_secret(rcipher, &rsec)),
                },
                packet: KeyPair {
                    local: Box::new(BoringPacketKey::from_secret(wcipher, &wsec)),
                    remote: Box::new(BoringPacketKey::from_secret(rcipher, &rsec)),
                },
            };
            if next_level == ffi::ssl_encryption_level_t::ssl_encryption_application {
                self.app_secrets = Some((wcipher, wsec, rsec));
            }
            self.current_level = next_level;
            return Some(keys);
        }

        None
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let (cipher, local_sec, remote_sec) = self.app_secrets.as_mut()?;
        let mut next_local = vec![0u8; cipher.hash_len()];
        let mut next_remote = vec![0u8; cipher.hash_len()];
        hkdf_expand_label(*cipher, local_sec, b"quic ku", &mut next_local);
        hkdf_expand_label(*cipher, remote_sec, b"quic ku", &mut next_remote);
        *local_sec = next_local;
        *remote_sec = next_remote;
        Some(KeyPair {
            local: Box::new(BoringPacketKey::from_secret(*cipher, local_sec)),
            remote: Box::new(BoringPacketKey::from_secret(*cipher, remote_sec)),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        if payload.len() < 16 {
            return false;
        }
        let tag_start = payload.len() - 16;
        let mut pseudo_packet = Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + tag_start);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        pseudo_packet.extend_from_slice(&payload[..tag_start]);

        let tag = &payload[tag_start..];
        let mut ctx: ffi::EVP_AEAD_CTX = unsafe { std::mem::zeroed() };
        let mut out_len: usize = 0;
        let ok = unsafe {
            if ffi::EVP_AEAD_CTX_init(
                &mut ctx,
                ffi::EVP_aead_aes_128_gcm(),
                RETRY_INTEGRITY_KEY_V1.as_ptr(),
                RETRY_INTEGRITY_KEY_V1.len(),
                16,
                ptr::null_mut(),
            ) != 1
            {
                return false;
            }
            let res = ffi::EVP_AEAD_CTX_open(
                &ctx,
                ptr::null_mut(),
                &mut out_len,
                0,
                RETRY_INTEGRITY_NONCE_V1.as_ptr(),
                RETRY_INTEGRITY_NONCE_V1.len(),
                tag.as_ptr(),
                tag.len(),
                pseudo_packet.as_ptr(),
                pseudo_packet.len(),
            );
            ffi::EVP_AEAD_CTX_cleanup(&mut ctx);
            res
        };
        ok == 1
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let ok = unsafe {
            ffi::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr() as *const c_char,
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if ok == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}
