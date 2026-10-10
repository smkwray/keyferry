//! Controller-owned capture. Frames/OCR are transient response bodies, never events or logs.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use keyferry_capture::{
    capture,
    frames::{Capture, Frame, FrameSource, Region, Retry, FRAME_WAIT, MAX_SIDE},
    ocr::{NativeOcr, Ocr},
};
use std::sync::atomic::AtomicBool;

pub(crate) const MAX_WIRE: usize = 7 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct Service {
    inventory: Option<(Instant, Result<Vec<capture::Device>, &'static str>)>,
    streams: HashMap<String, Capture>,
    inventory_retry: Retry,
    source_retry: Retry,
    last_request: Option<Instant>,
    #[cfg(test)]
    pub fake: Option<Frame>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrameRequest {
    pub device: String,
    pub source: String,
    pub after: Option<u64>,
    pub epoch: Option<String>,
    pub region: Option<Region>,
    pub max_width: Option<u32>,
    #[serde(default)]
    pub ocr: bool,
}

impl Service {
    pub(crate) fn stop(&mut self) {
        self.streams.clear();
    }
    fn devices(&mut self) -> Result<Vec<capture::Device>, &'static str> {
        self.devices_at(Instant::now(), capture::devices)
    }
    fn devices_at(
        &mut self,
        now: Instant,
        discover: impl FnOnce() -> Result<Vec<capture::Device>, &'static str>,
    ) -> Result<Vec<capture::Device>, &'static str> {
        if let Some((at, Ok(devices))) = &self.inventory {
            if now.saturating_duration_since(*at) < Duration::from_secs(10) {
                return Ok(devices.clone());
            }
        }
        let result = self.inventory_retry.attempt(now, || {
            let devices = discover()?;
            if devices.is_empty() {
                return Err("capture.source_unavailable");
            }
            Ok(devices)
        });
        self.inventory = Some((now, result.clone()));
        result
    }

    fn sources(&mut self) -> serde_json::Value {
        #[cfg(test)]
        if self.fake.is_some() {
            return serde_json::json!({"sources":[{"id":"local:fake-hdmi","name":"Fake HDMI capture","recognized":true,"controller":"local"}],"error":null});
        }
        match self.devices() {
            Ok(devices) => serde_json::json!({"sources": devices.iter().map(|d| serde_json::json!({
                "id":format!("local:{}",d.id),"name":d.name,"recognized":capture::recognized(d),"controller":"local"})).collect::<Vec<_>>(),"error":null}),
            Err(code) => serde_json::json!({"sources":[],"error":code}),
        }
    }

    fn frame(&mut self, request: &FrameRequest) -> Result<serde_json::Value, &'static str> {
        if self
            .last_request
            .is_some_and(|at| at.elapsed() < Duration::from_millis(100))
        {
            return Err("capture.rate_limit");
        }
        self.last_request = Some(Instant::now());
        if request
            .max_width
            .is_some_and(|w| !(2..=MAX_SIDE).contains(&w))
        {
            return Err("capture.scale");
        }
        #[cfg(test)]
        if let Some(frame) = &self.fake {
            if request.source != "local:fake-hdmi" {
                return Err("capture.source_not_found");
            }
            let mut frame = frame.clone();
            frame.at = Instant::now();
            frame.serial = request.after.unwrap_or(0) + 1;
            return encode(
                &frame,
                request,
                serde_json::json!({"generation":frame.generation,"source":"local:fake-hdmi"}),
            );
        }
        let mut retry = std::mem::take(&mut self.source_retry);
        let result = retry.attempt(Instant::now(), || self.frame_inner(request));
        self.source_retry = retry;
        result
    }

    fn frame_inner(&mut self, request: &FrameRequest) -> Result<serde_json::Value, &'static str> {
        let id = request
            .source
            .strip_prefix("local:")
            .ok_or("capture.source_not_found")?;
        if !self.streams.contains_key(id) {
            let devices = self.devices()?;
            capture::select_source(&devices, Some(id)).map_err(|_| "capture.source_unavailable")?;
            if self.streams.len() >= 4 {
                return Err("capture.stream_limit");
            }
            self.streams
                .insert(id.to_owned(), Capture::start(Some(id.to_owned())));
        }
        let capture = self.streams.get_mut(id).expect("stream");
        let frame = capture.latest(request.after, FRAME_WAIT, &AtomicBool::new(false))?;
        encode(&frame, request, capture.status())
    }
}

fn encode(
    frame: &Frame,
    request: &FrameRequest,
    status: serde_json::Value,
) -> Result<serde_json::Value, &'static str> {
    if frame.width == 0
        || frame.height == 0
        || frame.width > MAX_SIDE
        || frame.height > MAX_SIDE
        || frame.rgb.len() != (frame.width * frame.height * 3) as usize
    {
        return Err("capture.size_limit");
    }
    let region = request.region.unwrap_or(Region {
        x: 0,
        y: 0,
        width: frame.width,
        height: frame.height,
    });
    if !region.valid(frame) {
        return Err("capture.region");
    }
    let max_width = request.max_width.unwrap_or(MAX_SIDE);
    if !(2..=MAX_SIDE).contains(&max_width) {
        return Err("capture.scale");
    }
    let ratio = (f64::from(max_width) / f64::from(region.width)).min(1.0);
    let width = (f64::from(region.width) * ratio).round().max(1.0) as u32;
    let height = (f64::from(region.height) * ratio).round().max(1.0) as u32;
    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    for y in 0..height {
        for x in 0..width {
            let sx = region.x + x * region.width / width;
            let sy = region.y + y * region.height / height;
            let i = ((sy * frame.width + sx) * 3) as usize;
            rgb.extend_from_slice(&frame.rgb[i..i + 3]);
        }
    }
    let scaled = Frame {
        width,
        height,
        rgb,
        ..frame.clone()
    };
    let png = scaled.png()?;
    if png.len() > 5 * 1024 * 1024 {
        return Err("capture.size_limit");
    }
    let boxes = if request.ocr {
        Some(NativeOcr.recognize(&scaled)?)
    } else {
        None
    };
    let (signal, mean_luma) = capture::signal(&frame.rgb);
    let result = serde_json::json!({"signal":signal,"mean_luma":mean_luma,"schema":"keyferry.capture-live.v1","png":STANDARD.encode(png),
        "width":width,"height":height,"native":frame.native,"serial":frame.serial,"generation":frame.generation,
        "age_ms":frame.at.elapsed().as_millis(),"region":region,"capture":status,"boxes":boxes});
    if serde_json::to_vec(&result)
        .map_err(|_| "capture.encode")?
        .len()
        > MAX_WIRE
    {
        return Err("capture.size_limit");
    }
    Ok(result)
}

async fn local_sources(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &daemon)?;
    let service = daemon.0.capture.clone();
    let permit = daemon
        .0
        .capture_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::conflict("capture.busy"))?;
    let mut result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service.lock().expect("capture service").sources()
    })
    .await
    .map_err(|_| ApiError::internal("capture.worker"))?;
    if let Some(forwarder) = daemon.forwarder() {
        let (sources, errors) = forwarder.capture_sources().await;
        result["sources"]
            .as_array_mut()
            .expect("sources")
            .extend(sources);
        result["peer_errors"] = serde_json::json!(errors);
    }
    Ok(Json(result))
}

async fn peer_sources(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &daemon)?;
    require_owner_channel(&headers)?;
    daemon.lookup(&id)?;
    let service = daemon.0.capture.clone();
    let permit = daemon
        .0
        .capture_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::conflict("capture.busy"))?;
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            service.lock().expect("capture service").sources()
        })
        .await
        .map_err(|_| ApiError::internal("capture.worker"))?,
    ))
}

fn require_owner_channel(headers: &HeaderMap) -> Result<(), ApiError> {
    if !headers.contains_key(VERIFIED_OWNER_CALLER_HEADER) {
        return Err(ApiError::auth("capture.owner_mtls_required"));
    }
    Ok(())
}

fn admit(daemon: &Daemon) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    daemon
        .0
        .capture_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::conflict("capture.busy"))
}

async fn local_frame(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<FrameRequest>,
) -> Result<Response, ApiError> {
    authorize(&headers, &daemon)?;
    let permit = admit(&daemon)?;
    // Only loopback exposes this route; a source never contains an address supplied by a client.
    if request.source.starts_with("local:") {
        return serve_frame(daemon, request, permit).await;
    }
    let forwarder = daemon
        .forwarder()
        .ok_or_else(|| ApiError::unavailable("capture.peer_offline"))?;
    let _permit = permit;
    Ok(forwarder.capture_frame(&daemon, request).await)
}

async fn peer_frame(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<FrameRequest>,
) -> Result<Response, ApiError> {
    require_owner_channel(&headers)?;
    authorize(&headers, &daemon)?;
    let permit = admit(&daemon)?;
    if request.device != id {
        return Err(ApiError::bad_request("capture.device_mismatch"));
    }
    daemon.lookup(&id)?;
    if daemon.local_link_authenticated(&id) {
        authorize_owner_mutation(&headers, &daemon, &id)?;
    } else {
        // Eyes need not hold hands. Reprove our own authorized device through its actual holder;
        // this does not forward the frame request, input, or caller credentials.
        let forwarder = daemon
            .forwarder()
            .ok_or_else(|| ApiError::unavailable("capture.device_unavailable"))?;
        if !forwarder.capture_prove_device(&id).await {
            return Err(ApiError::auth("capture.fresh_proof_required"));
        }
    }
    serve_frame(daemon, request, permit).await
}

async fn serve_frame(
    daemon: Daemon,
    mut request: FrameRequest,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let service = daemon.0.capture.clone();
    let epoch = daemon.0.epoch;
    if request.epoch.as_deref() != Some(&epoch.to_string()) {
        request.after = None;
    }
    let mut result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service.lock().expect("capture service").frame(&request)
    })
    .await
    .map_err(|_| ApiError::internal("capture.worker"))?
    .map_err(ApiError::unavailable)?;
    result["epoch"] = serde_json::json!(epoch);
    Ok(Json(result).into_response())
}

pub(crate) fn local_routes() -> Router<Daemon> {
    Router::new()
        .route("/v1/capture/sources", get(local_sources))
        .route(
            "/v1/capture/frame",
            post(local_frame).layer(DefaultBodyLimit::max(4096)),
        )
}
pub(crate) fn peer_routes() -> Router<Daemon> {
    Router::new()
        .route("/v1/devices/{id}/capture/sources", get(peer_sources))
        .route(
            "/v1/devices/{id}/capture/frame",
            post(peer_frame).layer(DefaultBodyLimit::max(4096)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_inventory_is_inert_without_clients_and_backoff_is_on_demand() {
        let mut service = Service::default();
        let mut discoveries = Vec::new();
        let start = Instant::now();
        assert!(service.inventory.is_none());
        assert!(service.streams.is_empty());
        for second in 0..=240 {
            let result = service.devices_at(start + Duration::from_secs(second), || {
                discoveries.push(second);
                Ok(Vec::new())
            });
            assert_eq!(result.unwrap_err(), "capture.source_unavailable");
        }
        assert_eq!(discoveries, [0, 2, 6, 14, 30, 62, 122, 182]);
        assert!(service.streams.is_empty());
        assert_eq!(service.sources()["error"], "capture.source_unavailable");
    }
    #[test]
    fn region_scale_and_frame_bounds_are_checked_on_the_served_frame() {
        let frame = Frame {
            width: 32,
            height: 24,
            native: (64, 48),
            rgb: vec![50; 32 * 24 * 3],
            serial: 1,
            generation: 1,
            at: Instant::now(),
        };
        let mut request = FrameRequest {
            device: String::new(),
            source: "local:fake".into(),
            after: None,
            epoch: None,
            region: Some(Region {
                x: 2,
                y: 3,
                width: 16,
                height: 10,
            }),
            max_width: Some(8),
            ocr: false,
        };
        let v = encode(&frame, &request, serde_json::json!({})).unwrap();
        assert_eq!(v["width"], 8);
        assert_eq!(v["height"], 5);
        request.region.as_mut().unwrap().x = 30;
        assert_eq!(
            encode(&frame, &request, serde_json::json!({})).unwrap_err(),
            "capture.region"
        );
        request.region = None;
        request.max_width = Some(1281);
        assert_eq!(
            encode(&frame, &request, serde_json::json!({})).unwrap_err(),
            "capture.scale"
        );
    }
    #[tokio::test]
    #[ignore = "requires a real HDMI capture card; read-only isolated daemon, no stick commands"]
    async fn real_capture_through_isolated_daemon_http_api() {
        use axum::body::{to_bytes, Body};
        use tower_service::Service;
        let daemon = Daemon::new(MemoryTokenStore::new("capture-smoke-token")).unwrap();
        let mut router = daemon.router();
        let response = router
            .call(
                Request::builder()
                    .uri("/v1/capture/sources")
                    .header(header::AUTHORIZATION, "Bearer capture-smoke-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let inventory: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_WIRE).await.unwrap())
                .unwrap();
        let sources = inventory["sources"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["recognized"] == true)
            .collect::<Vec<_>>();
        assert_eq!(
            sources.len(),
            1,
            "requires exactly one recognized local HDMI source"
        );
        let body = serde_json::json!({"device":"","source":sources[0]["id"]}).to_string();
        let deadline = Instant::now() + Duration::from_secs(25);
        let result = loop {
            let response = router
                .call(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/capture/frame")
                        .header(header::AUTHORIZATION, "Bearer capture-smoke-token")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), MAX_WIRE).await.unwrap())
                    .unwrap();
            if status == StatusCode::OK {
                break value;
            }
            assert!(
                Instant::now() < deadline,
                "read-only capture timed out: HTTP {status}"
            );
            time::sleep(Duration::from_millis(150)).await;
        };
        assert!(result["width"].as_u64().unwrap() <= 1280);
        assert!(
            STANDARD
                .decode(result["png"].as_str().unwrap())
                .unwrap()
                .len()
                < 5 * 1024 * 1024
        );
        assert!(daemon.metadata().is_empty());
        println!("read-only real capture: {}x{}, native={}, frame_age_ms={}, memory-only; no stick commands",
            result["width"],result["height"],result["native"],result["age_ms"]);
        daemon.shutdown(Duration::from_secs(5)).await;
    }
}
