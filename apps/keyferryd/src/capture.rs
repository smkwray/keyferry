//! Controller-owned capture. Frames/OCR are transient response bodies, never events or logs.
//!
//! Admission is per source: one request in flight per source (a second reader of the same
//! source gets `capture.busy` and shares the one held stream), while different sources never
//! wait on each other. PNG/OCR encoding additionally takes a small CPU-sized global permit.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use keyferry_capture::{
    capture,
    frames::{Capture, Frame, FrameSource, Region, Retry, FRAME_WAIT, MAX_SIDE},
    ocr::{NativeOcr, Ocr},
};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
};

pub(crate) const MAX_WIRE: usize = 7 * 1024 * 1024;
const MAX_STREAMS: usize = 4;
/// Local streams plus forwarded peer sources; bounds retained frames and blocking workers.
const MAX_IN_FLIGHT: usize = 8;

pub(crate) struct Service {
    inventory: Mutex<Inventory>,
    streams: Mutex<Streams>,
    in_flight: Mutex<HashSet<String>>,
    closed: AtomicBool,
    encoders: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub fake: Mutex<HashMap<String, Frame>>,
    #[cfg(test)]
    pub fake_wait: Mutex<Duration>,
}

#[derive(Default)]
struct Inventory {
    cached: Option<(Instant, Result<Vec<capture::Device>, &'static str>)>,
    retry: Retry,
}

#[derive(Default)]
struct Streams {
    stopped: bool,
    by_source: HashMap<String, Arc<Mutex<Stream>>>,
}

struct Stream {
    capture: Capture,
    retry: Retry,
    last_request: Option<Instant>,
}

/// One admitted request for one source; released when the request's work finishes.
pub(crate) struct Admission {
    service: Arc<Service>,
    source: String,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.service
            .in_flight
            .lock()
            .expect("capture admission")
            .remove(&self.source);
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrameRequest {
    pub device: String,
    pub source: String,
    pub after: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub epoch: Option<String>,
    pub region: Option<Region>,
    pub max_width: Option<u32>,
    #[serde(default)]
    pub ocr: bool,
}

impl Default for Service {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(2, usize::from);
        Self {
            inventory: Mutex::default(),
            streams: Mutex::default(),
            in_flight: Mutex::default(),
            closed: AtomicBool::new(false),
            encoders: Arc::new(tokio::sync::Semaphore::new(
                (cpus / 2).clamp(2, MAX_STREAMS),
            )),
            #[cfg(test)]
            fake: Mutex::default(),
            #[cfg(test)]
            fake_wait: Mutex::default(),
        }
    }
}

impl Service {
    pub(crate) fn admit(self: &Arc<Self>, source: &str) -> Result<Admission, &'static str> {
        let mut in_flight = self.in_flight.lock().expect("capture admission");
        if self.closed.load(Ordering::Acquire)
            || in_flight.len() >= MAX_IN_FLIGHT
            || !in_flight.insert(source.to_owned())
        {
            return Err("capture.busy");
        }
        Ok(Admission {
            service: self.clone(),
            source: source.to_owned(),
        })
    }

    /// Refuses new requests; `stop` then releases every held stream.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.encoders.close();
    }

    pub(crate) fn stop(&self) {
        let released = {
            let mut streams = self.streams.lock().expect("capture streams");
            streams.stopped = true;
            std::mem::take(&mut streams.by_source)
        };
        drop(released);
    }

    fn devices(&self) -> Result<Vec<capture::Device>, &'static str> {
        self.devices_at(Instant::now(), capture::devices)
    }
    fn devices_at(
        &self,
        now: Instant,
        discover: impl FnOnce() -> Result<Vec<capture::Device>, &'static str>,
    ) -> Result<Vec<capture::Device>, &'static str> {
        // Discovery is serialized and cached; held streams never wait on it.
        let mut inventory = self.inventory.lock().expect("capture inventory");
        if let Some((at, Ok(devices))) = &inventory.cached {
            if now.saturating_duration_since(*at) < Duration::from_secs(10) {
                return Ok(devices.clone());
            }
        }
        let result = inventory.retry.attempt(now, || {
            let devices = discover()?;
            if devices.is_empty() {
                return Err("capture.source_unavailable");
            }
            Ok(devices)
        });
        inventory.cached = Some((now, result.clone()));
        result
    }

    fn sources(&self) -> serde_json::Value {
        #[cfg(test)]
        {
            let fake = self.fake.lock().expect("fake capture");
            if !fake.is_empty() {
                let mut ids = fake.keys().collect::<Vec<_>>();
                ids.sort();
                return serde_json::json!({"sources": ids.iter().map(|id| serde_json::json!({
                    "id":format!("local:{id}"),"name":format!("Fake capture {id}"),"recognized":true,"controller":"local"})).collect::<Vec<_>>(),"error":null});
            }
        }
        match self.devices() {
            Ok(devices) => serde_json::json!({"sources": devices.iter().map(|d| serde_json::json!({
                "id":format!("local:{}",d.id),"name":d.name,"recognized":capture::recognized(d),"controller":"local"})).collect::<Vec<_>>(),"error":null}),
            Err(code) => serde_json::json!({"sources":[],"error":code}),
        }
    }

    /// The held stream for one source, opened on first use. Only the map lookup is shared.
    fn stream(&self, id: &str) -> Result<Arc<Mutex<Stream>>, &'static str> {
        if let Some(stream) = self
            .streams
            .lock()
            .expect("capture streams")
            .by_source
            .get(id)
        {
            return Ok(stream.clone());
        }
        #[cfg(test)]
        let faked = {
            let fake = self.fake.lock().expect("fake capture");
            if !fake.is_empty() && !fake.contains_key(id) {
                return Err("capture.source_not_found");
            }
            !fake.is_empty()
        };
        #[cfg(not(test))]
        let faked = false;
        if !faked {
            let devices = self.devices()?;
            capture::select_source(&devices, Some(id)).map_err(|_| "capture.source_unavailable")?;
        }
        let mut streams = self.streams.lock().expect("capture streams");
        if streams.stopped {
            return Err("capture.busy");
        }
        if !streams.by_source.contains_key(id) && streams.by_source.len() >= MAX_STREAMS {
            return Err("capture.stream_limit");
        }
        Ok(streams
            .by_source
            .entry(id.to_owned())
            .or_insert_with(|| {
                Arc::new(Mutex::new(Stream {
                    capture: Capture::start(Some(id.to_owned())),
                    retry: Retry::default(),
                    last_request: None,
                }))
            })
            .clone())
    }

    /// Waits for this source's next frame. Holds only this source's stream.
    fn frame(
        &self,
        request: &FrameRequest,
    ) -> Result<(Arc<Frame>, serde_json::Value), &'static str> {
        let timeout = request.timeout()?;
        if request
            .max_width
            .is_some_and(|w| !(2..=MAX_SIDE).contains(&w))
        {
            return Err("capture.scale");
        }
        let id = request
            .source
            .strip_prefix("local:")
            .ok_or("capture.source_not_found")?;
        let stream = self.stream(id)?;
        let mut stream = stream.lock().expect("capture stream");
        if stream
            .last_request
            .is_some_and(|at| at.elapsed() < Duration::from_millis(100))
        {
            return Err("capture.rate_limit");
        }
        stream.last_request = Some(Instant::now());
        #[cfg(test)]
        let fake = self.fake.lock().expect("fake capture").get(id).cloned();
        #[cfg(test)]
        if let Some(mut frame) = fake {
            let wait = *self.fake_wait.lock().expect("fake wait");
            std::thread::sleep(wait);
            frame.at = Instant::now();
            frame.serial = request.after.unwrap_or(0) + 1;
            return Ok((
                Arc::new(frame),
                serde_json::json!({"generation":1,"source":request.source}),
            ));
        }
        let Stream { capture, retry, .. } = &mut *stream;
        let result = retry.attempt(Instant::now(), || {
            capture.latest(request.after, timeout, &AtomicBool::new(false))
        });
        // A short caller observation deadline is not a failed source or permission to reopen it.
        if result.as_ref().err() == Some(&"capture.frame_timeout") {
            *retry = Retry::default();
        }
        Ok((result?, capture.status()))
    }
}

impl FrameRequest {
    fn timeout(&self) -> Result<Duration, &'static str> {
        match self.timeout_ms {
            Some(ms) if (1..=FRAME_WAIT.as_millis() as u64).contains(&ms) => {
                Ok(Duration::from_millis(ms))
            }
            Some(_) => Err("capture.timeout"),
            None => Ok(FRAME_WAIT),
        }
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
    let scaled = if region.x == 0 && region.y == 0 && (width, height) == (frame.width, frame.height)
    {
        std::borrow::Cow::Borrowed(frame)
    } else {
        let mut rgb = Vec::with_capacity((width * height * 3) as usize);
        for y in 0..height {
            for x in 0..width {
                let sx = region.x + x * region.width / width;
                let sy = region.y + y * region.height / height;
                let i = ((sy * frame.width + sx) * 3) as usize;
                rgb.extend_from_slice(&frame.rgb[i..i + 3]);
            }
        }
        std::borrow::Cow::Owned(Frame {
            width,
            height,
            rgb,
            native: frame.native,
            serial: frame.serial,
            generation: frame.generation,
            at: frame.at,
        })
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

async fn list_sources(daemon: &Daemon) -> Result<serde_json::Value, ApiError> {
    let service = daemon.0.capture.clone();
    if service.closed.load(Ordering::Acquire) {
        return Err(ApiError::conflict("capture.busy"));
    }
    tokio::task::spawn_blocking(move || service.sources())
        .await
        .map_err(|_| ApiError::internal("capture.worker"))
}

async fn local_sources(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &daemon)?;
    let mut result = list_sources(&daemon).await?;
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
    Ok(Json(list_sources(&daemon).await?))
}

fn require_owner_channel(headers: &HeaderMap) -> Result<(), ApiError> {
    if !headers.contains_key(VERIFIED_OWNER_CALLER_HEADER) {
        return Err(ApiError::auth("capture.owner_mtls_required"));
    }
    Ok(())
}

fn admit(daemon: &Daemon, request: &FrameRequest) -> Result<Admission, ApiError> {
    daemon
        .0
        .capture
        .admit(&request.source)
        .map_err(ApiError::conflict)
}

async fn local_frame(
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<FrameRequest>,
) -> Result<Response, ApiError> {
    authorize(&headers, &daemon)?;
    let admission = admit(&daemon, &request)?;
    let timeout = request.timeout().map_err(ApiError::bad_request)?;
    // Only loopback exposes this route; a source never contains an address supplied by a client.
    if request.source.starts_with("local:") {
        return serve_frame(daemon, request, admission).await;
    }
    let forwarder = daemon
        .forwarder()
        .ok_or_else(|| ApiError::unavailable("capture.peer_offline"))?;
    let _admission = admission;
    tokio::time::timeout(timeout, forwarder.capture_frame(&daemon, request))
        .await
        .map_err(|_| ApiError::unavailable("capture.frame_timeout"))
}

async fn peer_frame(
    Path(id): Path<String>,
    State(daemon): State<Daemon>,
    headers: HeaderMap,
    Json(request): Json<FrameRequest>,
) -> Result<Response, ApiError> {
    require_owner_channel(&headers)?;
    authorize(&headers, &daemon)?;
    let admission = admit(&daemon, &request)?;
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
    serve_frame(daemon, request, admission).await
}

/// The admission moves into each blocking phase, so an abandoned HTTP request keeps its source
/// admitted until the worker that still holds the stream finishes.
async fn serve_frame(
    daemon: Daemon,
    mut request: FrameRequest,
    admission: Admission,
) -> Result<Response, ApiError> {
    let service = daemon.0.capture.clone();
    let epoch = daemon.0.epoch;
    if request.epoch.as_deref() != Some(&epoch.to_string()) {
        request.after = None;
    }
    let (admission, request, captured) = tokio::task::spawn_blocking(move || {
        let captured = service.frame(&request);
        (admission, request, captured)
    })
    .await
    .map_err(|_| ApiError::internal("capture.worker"))?;
    let (frame, status) = captured.map_err(ApiError::unavailable)?;
    let encoder = daemon
        .0
        .capture
        .encoders
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::conflict("capture.busy"))?;
    let mut result = tokio::task::spawn_blocking(move || {
        let _held = (admission, encoder);
        encode(&frame, &request, status)
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
    fn frame_deadline_is_optional_bounded_and_validated_before_capture() {
        let value = serde_json::json!({"device":"test","source":"local:fake"});
        let mut request: FrameRequest = serde_json::from_value(value).unwrap();
        assert_eq!(request.timeout().unwrap(), FRAME_WAIT);
        request.timeout_ms = Some(3000);
        assert_eq!(request.timeout().unwrap(), Duration::from_secs(3));
        for ms in [0, FRAME_WAIT.as_millis() as u64 + 1, u64::MAX] {
            request.timeout_ms = Some(ms);
            let service = Service::default();
            assert_eq!(service.frame(&request).unwrap_err(), "capture.timeout");
            assert!(service.streams.lock().unwrap().by_source.is_empty());
        }
    }

    #[test]
    fn absent_inventory_is_inert_without_clients_and_backoff_is_on_demand() {
        let service = Service::default();
        let mut discoveries = Vec::new();
        let start = Instant::now();
        assert!(service.inventory.lock().unwrap().cached.is_none());
        assert!(service.streams.lock().unwrap().by_source.is_empty());
        for second in 0..=240 {
            let result = service.devices_at(start + Duration::from_secs(second), || {
                discoveries.push(second);
                Ok(Vec::new())
            });
            assert_eq!(result.unwrap_err(), "capture.source_unavailable");
        }
        assert_eq!(discoveries, [0, 2, 6, 14, 30, 62, 122, 182]);
        assert!(service.streams.lock().unwrap().by_source.is_empty());
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
            timeout_ms: None,
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sources_are_admitted_independently_and_never_cross() {
        use axum::body::{to_bytes, Body};
        use tower_service::Service;
        const WAIT: Duration = Duration::from_millis(400);
        let daemon = Daemon::new(MemoryTokenStore::new("capture-token")).unwrap();
        for (id, value) in [("card-a", 40), ("card-b", 200)] {
            let frame = Frame {
                width: 32,
                height: 24,
                native: (64, 48),
                rgb: vec![value; 32 * 24 * 3],
                serial: 1,
                generation: 1,
                at: Instant::now(),
            };
            daemon
                .0
                .capture
                .fake
                .lock()
                .unwrap()
                .insert(id.into(), frame);
        }
        *daemon.0.capture.fake_wait.lock().unwrap() = WAIT;
        let request = |source: &str| {
            let mut router = daemon.router();
            let body = serde_json::json!({"device":"","source":format!("local:{source}")});
            async move {
                let response = router
                    .call(
                        Request::builder()
                            .method("POST")
                            .uri("/v1/capture/frame")
                            .header(header::AUTHORIZATION, "Bearer capture-token")
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let value: serde_json::Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), MAX_WIRE).await.unwrap(),
                )
                .unwrap();
                (status, value)
            }
        };
        let started = Instant::now();
        let (a, b, same) = tokio::join!(request("card-a"), request("card-b"), async {
            time::sleep(WAIT / 4).await;
            request("card-a").await
        });
        let elapsed = started.elapsed();
        // Different cards wait concurrently; the global lock made this take two waits.
        assert!(elapsed < WAIT * 3 / 2, "{elapsed:?}");
        assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
        assert_eq!(a.1["mean_luma"].as_f64().unwrap().round(), 40.0);
        assert_eq!(b.1["mean_luma"].as_f64().unwrap().round(), 200.0);
        assert_eq!(a.1["capture"]["source"], "local:card-a");
        assert_eq!(b.1["capture"]["source"], "local:card-b");
        // A second reader of the same card shares its one stream and is told to retry.
        assert_eq!(same.0, StatusCode::CONFLICT);
        assert_eq!(same.1["error"], "capture.busy");
        let service = &daemon.0.capture;
        assert!(service.in_flight.lock().unwrap().is_empty());
        assert_eq!(service.streams.lock().unwrap().by_source.len(), 2);
        // A missing card fails alone; the other card keeps serving.
        service.fake.lock().unwrap().remove("card-a");
        time::sleep(Duration::from_millis(110)).await;
        let (gone, ok) = tokio::join!(request("card-c"), request("card-b"));
        assert_eq!(gone.1["error"], "capture.source_not_found");
        assert_eq!(ok.0, StatusCode::OK);
        assert!(daemon.metadata().is_empty());
        daemon.shutdown(Duration::from_secs(1)).await;
        assert_eq!(request("card-b").await.1["error"], "capture.busy");
        assert!(service.streams.lock().unwrap().by_source.is_empty());
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
