use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use tokio::sync::{RwLock, mpsc};

use crate::model::{
    ActivityDraft, FindingView, ServiceSighting, SnifferEvent, host_is_bypassed,
};
use crate::pii::{FindingAction, MAX_BODY, Rules, rewrite_body};
use crate::platform::process_name;

#[derive(Clone)]
pub struct SnifferHandler {
    pub rules: Arc<RwLock<Rules>>,
    pub bypass: Arc<RwLock<HashSet<String>>>,
    pub events: mpsc::UnboundedSender<SnifferEvent>,
}

impl HttpHandler for SnifferHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let (host, path) = request_target(&req);
        if self.is_bypass(&host).await {
            return req.into();
        }
        let method = req.method().clone();
        if !is_upload(&method) {
            return req.into();
        }
        if content_length(&req).is_some_and(|length| length > MAX_BODY) {
            self.emit_activity(ctx, skipped(&method, &host, &path, "not scanned: too large"));
            return req.into();
        }

        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let encoded = req.headers().get(http::header::CONTENT_ENCODING).is_some();
        // Fail open: compressed bodies are forwarded untouched so browsers keep working.
        if encoded {
            self.emit_activity(
                ctx,
                skipped(
                    &method,
                    &host,
                    &path,
                    "not scanned: compressed body forwarded unchanged",
                ),
            );
            return req.into();
        }

        let (mut parts, body) = req.into_parts();
        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                self.emit_activity(
                    ctx,
                    skipped(
                        &method,
                        &host,
                        &path,
                        "not scanned: body read failed; request dropped",
                    ),
                );
                return bad_gateway();
            }
        };
        if bytes.len() > MAX_BODY {
            self.emit_activity(ctx, skipped(&method, &host, &path, "not scanned: too large"));
            parts.headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&bytes.len().to_string())
                    .unwrap_or(HeaderValue::from_static("0")),
            );
            return Request::from_parts(parts, Body::from(bytes)).into();
        }

        let rules = self.rules.read().await.clone();
        let rewritten = rewrite_body(content_type.as_deref(), bytes.to_vec(), &rules);
        if let Some(reason) = rewritten.skipped.clone() {
            let mut record = skipped(&method, &host, &path, &reason);
            record.detail = Some(reason);
            self.emit_activity(ctx, record);
        } else if rewritten.findings.is_empty() {
            self.emit_activity(
                ctx,
                ActivityDraft {
                    process_name: String::new(),
                    method: method.to_string(),
                    host: host.clone(),
                    path: path.clone(),
                    action: "clean".to_string(),
                    alert: false,
                    detail: Some("scanned: no cleartext PII".to_string()),
                    findings: Vec::new(),
                },
            );
        } else {
            let action = if rewritten
                .findings
                .iter()
                .any(|finding| finding.action == FindingAction::Masked)
            {
                "masked"
            } else {
                "allowed"
            };
            self.emit_activity(
                ctx,
                ActivityDraft {
                    process_name: String::new(),
                    method: method.to_string(),
                    host: host.clone(),
                    path: path.clone(),
                    action: action.to_string(),
                    alert: rewritten.alert,
                    detail: None,
                    findings: rewritten
                        .findings
                        .iter()
                        .map(FindingView::from_finding)
                        .collect(),
                },
            );
        }

        let length = rewritten.body.len();
        parts.headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).unwrap_or(HeaderValue::from_static("0")),
        );
        parts.headers.remove(http::header::TRANSFER_ENCODING);
        Request::from_parts(parts, Body::from(rewritten.body)).into()
    }

    async fn should_intercept_connect(&mut self, ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = connect_host(req);
        let bypass = self.is_bypass(&host).await;
        let mode = if bypass { "tunneled" } else { "inspected" };
        self.emit_service(
            ctx,
            ServiceSighting {
                process_name: String::new(),
                host,
                mode: mode.to_string(),
                scanned: false,
                pii: false,
            },
        );
        !bypass
    }
}

impl SnifferHandler {
    async fn is_bypass(&self, host: &str) -> bool {
        let hosts = self.bypass.read().await;
        host_is_bypassed(host, &hosts)
    }

    fn emit_activity(&self, ctx: &HttpContext, mut draft: ActivityDraft) {
        draft.process_name = process_name(ctx.client_addr);
        let _ = self.events.send(SnifferEvent::Activity(draft));
    }

    fn emit_service(&self, ctx: &HttpContext, mut sighting: ServiceSighting) {
        sighting.process_name = process_name(ctx.client_addr);
        let _ = self.events.send(SnifferEvent::Service(sighting));
    }
}

fn skipped(method: &Method, host: &str, path: &str, detail: &str) -> ActivityDraft {
    ActivityDraft {
        process_name: String::new(),
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        action: "skipped".to_string(),
        alert: false,
        detail: Some(detail.to_string()),
        findings: Vec::new(),
    }
}

fn is_upload(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn content_length(req: &Request<Body>) -> Option<usize> {
    req.headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn request_target(req: &Request<Body>) -> (String, String) {
    let host = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(':').next().unwrap_or(value).to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let path = req.uri().path();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    (host, path)
}

fn connect_host(req: &Request<Body>) -> String {
    if let Some(host) = req.uri().host() {
        return host.to_ascii_lowercase();
    }
    req.uri()
        .to_string()
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn bad_gateway() -> RequestOrResponse {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from(Bytes::from_static(
            b"PII Sniffer could not read the upload.",
        )))
        .expect("gateway response")
        .into()
}
