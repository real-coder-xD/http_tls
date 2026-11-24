// Language: Rust 2021 | File: src/ws.rs | Target: TLS-Impersonated Sync & Native Async WebSocket Bridge
use crate::{net_err, runtime};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashMap;
use std::sync::Arc;
use wreq::ws::message::{CloseCode, Message};

#[pyclass(name = "WebSocket")]
pub struct NativeWebSocket {
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    #[pyo3(get)]
    pub protocol: Option<String>,
    pub(crate) inner: Arc<tokio::sync::Mutex<Option<wreq::ws::WebSocket>>>,
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

#[pymethods]
impl NativeWebSocket {
    pub fn send_text(&self, py: Python<'_>, text: String) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::text(text)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::text(text)).await.map_err(net_err)
        })
    }

    pub fn send_bytes(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        py.allow_threads(move || {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
                ws.send(Message::binary(data)).await.map_err(net_err)
            })
        })
    }

    pub fn asend_bytes<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| PyRuntimeError::new_err("[request] WebSocket closed"))?;
            ws.send(Message::binary(data)).await.map_err(net_err)
        })
    }

    pub fn recv(&self, py: Python<'_>) -> PyResult<Option<(String, Py<PyBytes>)>> {
        let inner = Arc::clone(&self.inner);
        let res = py.allow_threads(move || -> PyResult<Option<(String, Vec<u8>)>> {
            runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let ws = match guard.as_mut() {
                    Some(w) => w,
                    None => return Ok(None),
                };
                match ws.recv().await {
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
                    Some(Err(e)) => Err(net_err(e)),
                }
            })
        })?;
        Ok(res.map(|(k, b)| (k, PyBytes::new(py, &b).unbind())))
    }

    pub fn arecv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = match guard.as_mut() {
                Some(w) => w,
                None => return Ok(None::<(String, Vec<u8>)>),
            };
            match ws.recv().await {
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
                Some(Err(e)) => Err(net_err(e)),
            }
        })
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn close(&self, py: Python<'_>, code: u16, reason: &str) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        let reason_str = reason.to_string();
        py.allow_threads(move || {
            runtime().block_on(async move {
                if let Some(ws) = inner.lock().await.take() {
                    let _ = ws.close(CloseCode::from(code), reason_str).await;
                }
                Ok(())
            })
        })
    }

    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn aclose<'py>(&self, py: Python<'py>, code: u16, reason: &str) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let reason_str = reason.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(ws) = inner.lock().await.take() {
                let _ = ws.close(CloseCode::from(code), reason_str).await;
            }
            Ok(())
        })
    }

    pub fn __repr__(&self) -> String {
        format!("<WebSocket [{}]>", self.status_code)
    }
}
