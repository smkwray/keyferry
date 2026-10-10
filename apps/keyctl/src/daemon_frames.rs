//! Thin loopback client. Capture/OCR ownership and peer authentication remain in keyferryd.
use super::*;
use keyferry_capture::ocr::TextBox;

pub(super) fn automatic_device(inventory: &Value) -> Result<Option<(String, &'static str)>, Value> {
    let devices = inventory["devices"]
        .as_array()
        .ok_or_else(|| failure("protocol.invalid_response"))?;
    let authenticated = devices
        .iter()
        .filter(|d| d["link"] == "authenticated")
        .collect::<Vec<_>>();
    let pointers = authenticated
        .iter()
        .filter(|d| {
            d["firmware"]["device_capability_mask"]
                .as_u64()
                .unwrap_or(0)
                & u64::from(keyferry_protocol::capability::POINTER_EXTENDED_V1)
                != 0
        })
        .collect::<Vec<_>>();
    let chosen = if pointers.len() == 1 {
        Some((pointers[0], "automatic-pointer"))
    } else if authenticated.len() == 1 {
        Some((&authenticated[0], "automatic-single"))
    } else {
        None
    };
    chosen
        .map(|(d, why)| {
            d["id"]
                .as_str()
                .map(|id| (id.to_owned(), why))
                .ok_or_else(|| failure("protocol.invalid_response"))
        })
        .transpose()
}

fn automatic_source(entries: &[Value]) -> Option<(String, &'static str)> {
    let recognized = entries
        .iter()
        .filter(|e| e["recognized"] == true)
        .collect::<Vec<_>>();
    let local = recognized
        .iter()
        .filter(|e| e["controller"] == "local")
        .collect::<Vec<_>>();
    let (chosen, why) = if local.len() == 1 {
        (*local[0], "automatic-local")
    } else if local.is_empty() && recognized.len() == 1 {
        (recognized[0], "automatic-remote")
    } else {
        return None;
    };
    chosen["id"].as_str().map(|id| (id.to_owned(), why))
}

pub(super) struct DaemonFrames {
    url: String,
    token: PathBuf,
    device: String,
    source: Option<String>,
    choice: &'static str,
    inventory: Option<(Instant, Value)>,
    status: Value,
    ocr: bool,
    boxes: Option<Vec<TextBox>>,
    epoch: Option<String>,
}

impl DaemonFrames {
    pub fn new(source: Option<String>, url: &str, token: &Path) -> Self {
        Self {
            url: url.into(),
            token: token.into(),
            device: String::new(),
            choice: if source.is_some() {
                "explicit"
            } else {
                "unselected"
            },
            source,
            inventory: None,
            status: json!({}),
            ocr: false,
            boxes: None,
            epoch: None,
        }
    }
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, &'static str> {
        self.request_with_timeout(method, path, body, None)
    }
    fn request_with_timeout(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<Value, &'static str> {
        let endpoint = super::super::parse_endpoint(&self.url).map_err(|_| "input.url")?;
        let token =
            super::super::load_token(&self.token).map_err(|_| "daemon.token_unavailable")?;
        let client = super::super::Client { endpoint, token };
        let response = client
            .request_raw_with_timeout(method, path, body, timeout)
            .map_err(|_| "daemon.unavailable")?;
        let value: Value =
            serde_json::from_str(&response.body).map_err(|_| "protocol.invalid_response")?;
        if response.status >= 400 {
            // Return only known fixed codes; never reflect a peer body or frame into diagnostics.
            return Err(match value["error"].as_str() {
                Some("capture.rate_limit" | "capture.busy") => "capture.busy",
                Some(
                    "capture.peer_offline_or_invalid_frame"
                    | "capture.peer_offline_or_select_source"
                    | "capture.peer_offline_or_fresh_proof_failed",
                ) => "capture.peer_offline",
                Some("capture.source_busy") => "capture.source_busy",
                Some("capture.source_not_found") => "capture.source_not_found",
                Some("capture.source_unavailable") => "capture.source_unavailable",
                Some("capture.frame_timeout") => "capture.frame_timeout",
                Some("ocr.unsupported_platform") => "ocr.unsupported_platform",
                Some("ocr.engine_unavailable") => "ocr.engine_unavailable",
                _ => "capture.frame_unavailable",
            });
        }
        Ok(value)
    }
}

impl FrameSource for DaemonFrames {
    fn device(&mut self, device: &str) {
        self.device = device.into();
    }
    fn sources(&mut self) -> Result<Value, &'static str> {
        if self
            .inventory
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() > Duration::from_secs(10))
        {
            let value = self.request("GET", "/v1/capture/sources", None)?;
            if !value["sources"].is_array() {
                return Err("protocol.invalid_response");
            }
            self.inventory = Some((Instant::now(), value));
        }
        Ok(self.inventory.as_ref().expect("inventory").1.clone())
    }
    fn resolve(&mut self) -> Result<(), &'static str> {
        let inventory = self.sources()?;
        let entries = inventory["sources"]
            .as_array()
            .ok_or("protocol.invalid_response")?;
        if self.choice.starts_with("automatic")
            && self.source.is_some()
            && automatic_source(entries)
                .as_ref()
                .is_none_or(|(id, _)| Some(id) != self.source.as_ref())
        {
            return Err(
                if entries
                    .iter()
                    .any(|e| e["id"].as_str() == self.source.as_deref())
                {
                    "capture.select_required"
                } else {
                    "capture.source_unavailable"
                },
            );
        }
        if entries.is_empty() {
            return Err("capture.source_unavailable");
        }
        if let Some(source) = &self.source {
            let matches = entries
                .iter()
                .filter(|e| {
                    e["id"] == *source
                        || e["name"] == *source
                        || e["id"]
                            .as_str()
                            .is_some_and(|id| id.strip_prefix("local:") == Some(source))
                })
                .collect::<Vec<_>>();
            if matches.is_empty() {
                return Err("capture.source_unavailable");
            }
            if matches.len() != 1 {
                return Err("capture.select_required");
            }
            self.source = matches[0]["id"].as_str().map(str::to_owned);
        } else if let Some((source, choice)) = automatic_source(entries) {
            self.source = Some(source);
            self.choice = choice;
        } else {
            if !entries.iter().any(|entry| entry["recognized"] == true) {
                return Err("capture.source_unavailable");
            }
            return Err("capture.select_required");
        }
        Ok(())
    }
    fn select(&mut self, source: &str) -> Result<(), &'static str> {
        let old = self.source.clone();
        let old_choice = self.choice;
        self.source = Some(source.into());
        self.choice = "selected";
        if let Err(e) = self.resolve() {
            self.source = old;
            self.choice = old_choice;
            return Err(e);
        }
        self.status = json!({});
        self.boxes = None;
        self.epoch = None;
        Ok(())
    }
    fn request_ocr(&mut self, ocr: bool) {
        self.ocr = ocr;
    }
    fn ocr_result(&mut self) -> Option<Vec<TextBox>> {
        self.boxes.take()
    }
    fn latest(
        &mut self,
        after: Option<u64>,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> Result<Arc<Frame>, &'static str> {
        self.resolve()?;
        if self.device.is_empty()
            && self
                .source
                .as_deref()
                .is_some_and(|s| !s.starts_with("local:"))
        {
            return Err("device.select_required");
        }
        let started = Instant::now();
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err("request.cancelled");
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err("capture.frame_timeout");
            }
            let request = json!({"device":self.device,"source":self.source,"after":after,"epoch":self.epoch,"ocr":self.ocr,"timeout_ms":remaining.as_millis().clamp(1, keyferry_capture::frames::FRAME_WAIT.as_millis())});
            let value = match self.request_with_timeout(
                "POST",
                "/v1/capture/frame",
                Some(&request.to_string()),
                Some(remaining),
            ) {
                Err(_) if started.elapsed() >= timeout => return Err("capture.frame_timeout"),
                Err("capture.busy" | "capture.frame_unavailable")
                    if started.elapsed() < timeout =>
                {
                    thread::sleep(
                        Duration::from_millis(100).min(timeout.saturating_sub(started.elapsed())),
                    );
                    continue;
                }
                other => other?,
            };
            let received_at = Instant::now();
            let png = STANDARD
                .decode(value["png"].as_str().ok_or("capture.invalid_frame")?)
                .map_err(|_| "capture.invalid_frame")?;
            let decoder = png::Decoder::new_with_limits(
                io::Cursor::new(png),
                png::Limits {
                    bytes: 5 * 1024 * 1024,
                },
            );
            let mut reader = decoder.read_info().map_err(|_| "capture.invalid_frame")?;
            let info = reader.info();
            if info.width > frames::MAX_SIDE
                || info.height > frames::MAX_SIDE
                || info.width == 0
                || info.height == 0
                || info.color_type != png::ColorType::Rgb
                || info.bit_depth != png::BitDepth::Eight
                || info.is_animated()
            {
                return Err("capture.invalid_frame");
            }
            let (width, height) = (info.width, info.height);
            let mut rgb = vec![0; reader.output_buffer_size().ok_or("capture.invalid_frame")?];
            reader
                .next_frame(&mut rgb)
                .map_err(|_| "capture.invalid_frame")?;
            reader.finish().map_err(|_| "capture.invalid_frame")?;
            let native: (u32, u32) = serde_json::from_value(value["native"].clone())
                .map_err(|_| "capture.invalid_frame")?;
            if value["width"].as_u64() != Some(u64::from(width))
                || value["height"].as_u64() != Some(u64::from(height))
                || !(1..=4096).contains(&native.0)
                || !(1..=4096).contains(&native.1)
                || value["epoch"]
                    .as_str()
                    .is_none_or(|s| uuid::Uuid::parse_str(s).is_err())
            {
                return Err("capture.invalid_frame");
            }
            let serial = value["serial"].as_u64().ok_or("capture.invalid_frame")?;
            let generation = value["generation"]
                .as_u64()
                .ok_or("capture.invalid_frame")?;
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(format!("{}:{generation}", value["epoch"]));
            let generation = u64::from_le_bytes(hash[..8].try_into().expect("hash"));
            let age = value["age_ms"]
                .as_u64()
                .filter(|age| *age < 2000)
                .ok_or("capture.stale_frame")?;
            if received_at.elapsed() + Duration::from_millis(age) >= Duration::from_secs(2) {
                return Err("capture.stale_frame");
            }
            if self.epoch.as_deref() == value["epoch"].as_str()
                && after.is_some_and(|n| serial <= n)
            {
                return Err("capture.stale_frame");
            }
            self.epoch = value["epoch"].as_str().map(str::to_owned);
            self.status = value["capture"].clone();
            self.status["generation"] = json!(generation);
            self.boxes = if self.ocr {
                Some(
                    serde_json::from_value(value["boxes"].clone())
                        .map_err(|_| "ocr.invalid_response")?,
                )
            } else {
                None
            };
            self.ocr = false;
            return Ok(Arc::new(Frame {
                width,
                height,
                native,
                rgb,
                serial,
                generation,
                at: received_at - Duration::from_millis(age),
            }));
        }
    }
    fn status(&self) -> Value {
        let mut result = self.status.clone();
        result["source"] = json!(self.source);
        result["selection"] = json!(self.choice);
        result["owner"] = json!("keyferryd");
        result["ocr"] = json!("capture-controller-native");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_source_returns_unavailable_without_requesting_a_frame() {
        for source in [None, Some("local:absent".into())] {
            let mut frames =
                DaemonFrames::new(source, "http://127.0.0.1:9", Path::new("missing-token"));
            frames.inventory = Some((
                Instant::now(),
                json!({"sources":[{"id":"local:webcam","name":"Webcam","recognized":false,"controller":"local"}]}),
            ));
            assert_eq!(frames.resolve(), Err("capture.source_unavailable"));
            assert_eq!(
                frames
                    .latest(None, Duration::from_secs(1), &AtomicBool::new(false))
                    .unwrap_err(),
                "capture.source_unavailable"
            );
        }
    }

    #[test]
    fn production_selection_never_uses_position_and_prefers_unique_pointer() {
        let d = |id, link, pointer| json!({"id":id,"link":link,"firmware":{"device_capability_mask":if pointer{0x08000000}else{0}}});
        for (devices, expected) in [
            (vec![], None),
            (vec![d("offline", "none", true)], None),
            (
                vec![d("one", "authenticated", false)],
                Some(("one", "automatic-single")),
            ),
            (
                vec![
                    d("one", "authenticated", false),
                    d("two", "authenticated", false),
                ],
                None,
            ),
            (
                vec![
                    d("one", "authenticated", false),
                    d("pointer", "authenticated", true),
                ],
                Some(("pointer", "automatic-pointer")),
            ),
            (
                vec![
                    d("pointer", "authenticated", true),
                    d("one", "authenticated", false),
                ],
                Some(("pointer", "automatic-pointer")),
            ),
            (
                vec![d("a", "authenticated", true), d("b", "authenticated", true)],
                None,
            ),
        ] {
            let actual = automatic_device(&json!({"devices":devices})).unwrap();
            assert_eq!(actual.as_ref().map(|(a, b)| (a.as_str(), *b)), expected);
        }
        assert!(automatic_device(&json!({})).is_err());
    }
    #[test]
    fn production_capture_selection_prefers_local_and_refuses_ambiguity() {
        let s = |id, controller, recognized| json!({"id":id,"controller":controller,"recognized":recognized});
        assert_eq!(automatic_source(&[]), None);
        assert_eq!(automatic_source(&[s("webcam", "local", false)]), None);
        assert_eq!(
            automatic_source(&[s("r", "peer", true)]),
            Some(("r".into(), "automatic-remote"))
        );
        assert_eq!(
            automatic_source(&[s("r", "peer", true), s("l", "local", true)]),
            Some(("l".into(), "automatic-local"))
        );
        assert_eq!(
            automatic_source(&[s("a", "local", true), s("b", "local", true)]),
            None
        );
        assert_eq!(
            automatic_source(&[s("a", "peer", true), s("b", "peer", true)]),
            None
        );
    }
}
