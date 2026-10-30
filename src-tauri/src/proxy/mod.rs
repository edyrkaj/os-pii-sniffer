mod ca;
mod handler;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc, oneshot};

pub use ca::{CaPaths, ensure_ca};

use crate::model::SnifferEvent;
use crate::pii::Rules;

use ca::{crypto_provider, load_authority};
use handler::SnifferHandler;

pub struct RunningProxy {
    pub port: u16,
    pub shutdown: oneshot::Sender<()>,
}

pub async fn start_proxy(
    rules: Arc<RwLock<Rules>>,
    bypass: Arc<RwLock<HashSet<String>>>,
    events: mpsc::UnboundedSender<SnifferEvent>,
    ca_dir: &Path,
) -> Result<RunningProxy, String> {
    let listener = bind_listener().await?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let paths = ensure_ca(ca_dir)?;
    let authority = load_authority(&paths)?;
    let provider = crypto_provider();
    let (shutdown, shutdown_rx) = oneshot::channel::<()>();
    let handler = SnifferHandler {
        rules,
        bypass,
        events,
    };
    let proxy = hudsucker::Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(provider)
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        if let Err(error) = proxy.start().await {
            eprintln!("PII Sniffer proxy stopped: {error}");
        }
    });
    Ok(RunningProxy { port, shutdown })
}

async fn bind_listener() -> Result<TcpListener, String> {
    let mut last_error = String::from("Could not bind a local proxy port.");
    for port in 8765..=8775 {
        match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    #[tokio::test]
    async fn forwards_the_upload_unchanged_and_records_pii() {
        let result = tokio::time::timeout(Duration::from_secs(20), mask_email()).await;
        result.expect("proxy test timed out").expect("proxy test");
    }

    async fn mask_email() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("pii-sniffer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        let received: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let upstream = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|error| error.to_string())?;
        let upstream_port = upstream
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let slot = received.clone();
        tokio::spawn(async move {
            let Ok((stream, _)) = upstream.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let slot = slot.clone();
                async move {
                    let bytes = req.into_body().collect().await.unwrap().to_bytes();
                    *slot.lock().unwrap() = Some(bytes.to_vec());
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                        bytes::Bytes::from_static(b"ok"),
                    )))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let running = start_proxy(
            Arc::new(RwLock::new(crate::pii::Rules::default())),
            Arc::new(RwLock::new(HashSet::new())),
            tx,
            &dir,
        )
        .await?;

        let payload = r#"{"email":"ada@example.com"}"#;
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", running.port))
            .await
            .map_err(|error| error.to_string())?;
        let request = format!(
            "POST http://127.0.0.1:{upstream_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        client
            .write_all(request.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        let response_text = String::from_utf8_lossy(&response);
        if !response_text.contains("200") {
            return Err(format!("upstream was not reached: {response_text}"));
        }

        let forwarded = received
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "upstream received no body".to_string())?;
        let forwarded = String::from_utf8(forwarded).map_err(|error| error.to_string())?;
        if forwarded != payload {
            return Err(format!("upload was modified: {forwarded}"));
        }
        let event = loop {
            let notice = rx
                .recv()
                .await
                .ok_or_else(|| "no activity event".to_string())?;
            if let crate::model::SnifferEvent::Activity(event) = notice {
                break event;
            }
        };
        if event.action != "detected" || !event.alert {
            return Err(format!("expected a detection alert, got {}", event.action));
        }
        if event.findings.first().map(|finding| finding.pii_type.as_str()) != Some("email") {
            return Err("activity event did not record the email finding".to_string());
        }
        let _ = running.shutdown.send(());
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
