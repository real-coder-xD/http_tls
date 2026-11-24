// Language: Rust 2021 | File: src/ws.rs | Target: Full-Duplex TLS-Impersonated Sync & Native Async WebSocket Bridge
use crate::{net_py_err as net_err, runtime};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use wreq::ws::message::{CloseCode, CloseFrame, Message};

type WsSink = Arc<tokio::sync::Mutex<Option<SplitSink<wreq::ws::WebSocket, Message>>>>;
type WsStream = Arc<tokio::sync::Mutex<Option<SplitStream<wreq::ws::WebSocket>>>>;

#[pyclass(name = "WebSocket")]
pub struct NativeWebSocket {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub protocol: Option<String>,
    sink: WsSink,
    stream: WsStream,
    cancel: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
}

impl NativeWebSocket {
    pub(crate) fn from_ws(
        status_code: u16,
        headers: HashMap<String, String>,
        protocol: Option<String>,
        ws: wreq::ws::WebSocket,
    ) -> Self {
        let (sink, stream) = ws.split();
        Self {
            status_code,
            headers,
            protocol,
            sink: Arc::new(tokio::sync::Mutex::new(Some(sink))),
            stream: Arc::new(tokio::sync::Mutex::new(Some(stream))),
            cancel: Arc::new(Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

fn ws_msg_to_tuple(msg: Message) -> (String, Vec<u8>) {
    match msg {
        Message::Text(t) => ("text".to_string(), t.as_str().as_bytes().to_vec()),
        Message::Binary(b) => ("binary".to_string(), b.to_vec()),
        Message::Ping(b) => ("ping".to_string(), b.to_vec()),
        Message::Pong(b) => ("pong".to_string(), b.to_vec()),
        Message::Close(frame) => {
            let reason = frame.map(|f| f.reason.as_str().to_string()).unwrap_or_default();
            ("close".to_string(), reason.into_bytes())
        }
    }
}

async fn recv_next_ws(
    stream: WsStream,
    cancel: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
) -> PyResult<Option<(String, Vec<u8>)>> {
    if cancelled.load(Ordering::Acquire) {
        return Ok(None);
    }
    let mut guard = stream.lock().await;
    if cancelled.load(Ordering::Acquire) {
        guard.take();
        return Ok(None);
    }
    let ws = match guard.as_mut() {
        Some(w) => w,
        None => return Ok(None),
    };
    tokio::select! {
        biased;
        _ = cancel.notified() => {
            guard.take();
            Ok(None)
        }
        item = ws.next() => {
            match item {
                None => {
                    guard.take();
                    Ok(None)
                }
                Some(Ok(msg)) => {
                    let out = ws_msg_to_tuple(msg);
                    if out.0 == "close" {
                        guard.take();
                    }
                    Ok(Some(out))
                }
                Some(Err(e)) => {
                    guard.take();
                    Err(net_err(e))
                }
            }
        }
    }
}

async fn close_ws_sink(
    sink: WsSink,
    cancel: Arc<Notify>,
    cancelled: Arc<AtomicBool>,
    code: u16,
    reason: String,
) {
    cancelled.store(true, Ordering::Release);
    cancel.notify_waiters();
    if let Some(mut s) = sink.lock().await.take() {
        let frame = CloseFrame {
            code: CloseCode::from(code),
            reason: reason.into(),
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async {
                let _ = s.send(Message::close(frame)).await;
                let _ = s.close().await;
            },
        )
        .await;
    }
}

#[pymethods]
impl NativeWebSocket {
    pub fn send_text(&self, py: Python<'_>, text: String) -> PyResult<()> {
        let sink = Arc::clone(&self.sink);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = sink.lock().await;
                let ws = guard
                    .as_mut()
                    .ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::text(text)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let sink = Arc::clone(&self.sink);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = sink.lock().await;
            let ws = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::text(text)).await.map_err(net_err)
        })
    }

    pub fn send_bytes(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<()> {
        let sink = Arc::clone(&self.sink);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = sink.lock().await;
                let ws = guard
                    .as_mut()
                    .ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::binary(data)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_bytes<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let sink = Arc::clone(&self.sink);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = sink.lock().await;
            let ws = guard
                .as_mut()
                .ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::binary(data)).await.map_err(net_err)
        })
    }

    pub fn recv(&self, py: Python<'_>) -> PyResult<Option<(String, Py<PyBytes>)>> {
        let stream = Arc::clone(&self.stream);
        let cancel = Arc::clone(&self.cancel);
        let cancelled = Arc::clone(&self.cancelled);
        let res = py.allow_threads(move || {
            runtime().block_on(recv_next_ws(stream, cancel, cancelled))
        })?;
        Ok(res.map(|(k, b)| (k, PyBytes::new(py, &b).unbind())))
    }

    pub fn arecv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let stream = Arc::clone(&self.stream);
        let cancel = Arc::clone(&self.cancel);
        let cancelled = Arc::clone(&self.cancelled);
        pyo3_async_runtimes::tokio::future_into_py(py, recv_next_ws(stream, cancel, cancelled))
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let sink = Arc::clone(&self.sink);
        let cancel = Arc::clone(&self.cancel);
        let cancelled = Arc::clone(&self.cancelled);
        let reason_str = reason.to_string();
        py.allow_threads(move || {
            runtime().block_on(close_ws_sink(sink, cancel, cancelled, code, reason_str));
            Ok(())
        })
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn aclose<'py>(&self, py: Python<'py>, code: u16, reason: &str) -> PyResult<Bound<'py, PyAny>> {
        let sink = Arc::clone(&self.sink);
        let cancel = Arc::clone(&self.cancel);
        let cancelled = Arc::clone(&self.cancelled);
        let reason_str = reason.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            close_ws_sink(sink, cancel, cancelled, code, reason_str).await;
            Ok(())
        })
    }

    pub fn __repr__(&self) -> String {
        format!("<WebSocket [{}]>", self.status_code)
    }
}
